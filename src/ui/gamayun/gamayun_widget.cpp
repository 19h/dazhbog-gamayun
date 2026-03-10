#include "ui/gamayun/gamayun.h"

#include "analysis/pattern_gen.h"
#include "debug/debug_dump.h"
#include "fontsettings.h"
#include "lumina/apply.h"
#include "lumina/codec.h"
#include "lumina/pulled_metadata.h"
#include "lumina/session.h"
#include "lumina/settings.h"
#include "ui/dialogs/lumina_bulk_diff_dialog.h"

#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QGridLayout>
#include <QImage>
#include <QMessageBox>
#include <QPainter>
#include <QtCore/qpointer.h>
#include <QPlainTextEdit>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <thread>
#include <utility>

namespace {

std::array<uint8_t, 16> computeFunctionHash(BinaryViewRef view, FunctionRef func)
{
	return lumina::computeFunctionHash(view, func);
}

std::unordered_map<uint64_t, FunctionRef> buildFunctionMap(BinaryViewRef data)
{
	std::unordered_map<uint64_t, FunctionRef> functionsByAddress;
	if (!data)
		return functionsByAddress;

	for (auto& function : data->GetAnalysisFunctionList())
		functionsByAddress.emplace(function->GetStart(), function);

	return functionsByAddress;
}

void cachePulledFunction(
	std::unordered_map<uint64_t, lumina::PullCacheEntry>& pullCache,
	uint64_t address,
	const lumina::PulledFunction& pulledFunction)
{
	lumina::PullCacheEntry cacheEntry;
	cacheEntry.have = true;
	cacheEntry.metadata = lumina::parsePulledMetadata(pulledFunction.data, address);
	cacheEntry.popularity = pulledFunction.popularity;
	cacheEntry.len = pulledFunction.len;
	cacheEntry.remoteName = pulledFunction.name;
	cacheEntry.raw = pulledFunction.data;
	pullCache[address] = std::move(cacheEntry);
}

struct PullResult
{
	bool success = false;
	QString error;
	size_t requested = 0;
	size_t found = 0;
	size_t skipped = 0;
	std::unordered_map<uint64_t, lumina::PullCacheEntry> cacheUpdates;
};

struct ApplyResult
{
	size_t applied = 0;
	size_t missing = 0;
	lumina::ApplyStats stats;
};

QString formatApplyStatsDetails(const lumina::ApplyStats& stats)
{
	QStringList details;
	if (stats.namesApplied > 0)
		details << QString("%1 renamed").arg(stats.namesApplied);
	if (stats.functionCommentsApplied > 0)
		details << QString("%1 function comments").arg(stats.functionCommentsApplied);
	if (stats.functionTypesApplied > 0)
		details << QString("%1 function types").arg(stats.functionTypesApplied);
	if (stats.addressCommentsApplied > 0)
		details << QString("%1 address comments").arg(stats.addressCommentsApplied);
	if (stats.stackVariablesApplied > 0)
		details << QString("%1 stack vars").arg(stats.stackVariablesApplied);
	if (stats.tagsApplied > 0)
		details << QString("%1 tags").arg(stats.tagsApplied);
	return details.join(", ");
}

void showMetadataInspector(QWidget* parent, const QString& title, const QString& text)
{
	QDialog dialog(parent);
	dialog.setWindowTitle(title);
	dialog.resize(1100, 760);

	auto* layout = new QVBoxLayout(&dialog);
	auto* editor = new QPlainTextEdit(&dialog);
	editor->setReadOnly(true);
	editor->setPlainText(text);
	editor->setLineWrapMode(QPlainTextEdit::NoWrap);
	editor->setFont(getMonospaceFont(editor));
	layout->addWidget(editor, 1);

	auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
	QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
	QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
	layout->addWidget(buttons);

	dialog.exec();
}

QImage makeGamayunSidebarIcon()
{
	constexpr int size = 28;
	QImage image(size, size, QImage::Format_ARGB32_Premultiplied);
	image.fill(Qt::transparent);

	QPainter painter(&image);
	painter.setRenderHint(QPainter::Antialiasing, true);

	const QRectF bounds(2.0, 2.0, size - 4.0, size - 4.0);
	QLinearGradient gradient(bounds.topLeft(), bounds.bottomRight());
	gradient.setColorAt(0.0, QColor(0x0f, 0x4c, 0x81));
	gradient.setColorAt(1.0, QColor(0x1f, 0x78, 0x8e));
	painter.setPen(Qt::NoPen);
	painter.setBrush(gradient);
	painter.drawRoundedRect(bounds, 7.0, 7.0);

	QPen border(QColor(255, 255, 255, 48));
	border.setWidthF(1.0);
	painter.setPen(border);
	painter.setBrush(Qt::NoBrush);
	painter.drawRoundedRect(bounds.adjusted(0.5, 0.5, -0.5, -0.5), 7.0, 7.0);

	QFont font;
	font.setBold(true);
	font.setPixelSize(17);
	painter.setFont(font);
	painter.setPen(QColor(0xf8, 0xf3, 0xe6));
	painter.drawText(bounds.adjusted(0.0, -0.5, 0.0, 0.0), Qt::AlignCenter, QStringLiteral("G"));

	return image;
}

}  // namespace

// GamayunWidget implementation
GamayunWidget::GamayunWidget(ViewFrame* frame, BinaryViewRef data)
	: SidebarWidget("Gamayun"), m_data(data), m_frame(frame)
{
	if (!m_data && frame)
	{
		auto view = frame->getCurrentViewInterface();
		if (view)
			m_data = view->getData();
	}

	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(4);

	// Create table
	m_table = new GamayunTableView(this, frame, m_data);
	m_model = static_cast<GamayunModel*>(m_table->model());
	m_model->setPullCache(&m_pullCache);
	layout->addWidget(m_table, 1);

	// Create compact button bar with just essential buttons
	QWidget* buttonBar = new QWidget(this);
	QGridLayout* buttonLayout = new QGridLayout(buttonBar);
	buttonLayout->setContentsMargins(0, 4, 0, 0);
	buttonLayout->setSpacing(4);

	m_refreshButton = new QPushButton("Refresh", buttonBar);
	m_pullSelected = new QPushButton("Pull", buttonBar);
	m_inspectPulled = new QPushButton("Inspect", buttonBar);
	m_applyPulled = new QPushButton("Apply", buttonBar);
	m_pullAll = new QPushButton("Pull All", buttonBar);
	m_applyPulledAll = new QPushButton("Apply All", buttonBar);

	// Row 0: Main actions for selected
	buttonLayout->addWidget(m_refreshButton, 0, 0);
	buttonLayout->addWidget(m_pullSelected, 0, 1);
	buttonLayout->addWidget(m_inspectPulled, 0, 2);
	buttonLayout->addWidget(m_applyPulled, 0, 3);

	// Row 1: Bulk actions for all functions
	buttonLayout->addWidget(m_pullAll, 1, 1);
	buttonLayout->addWidget(m_applyPulledAll, 1, 3);

	layout->addWidget(buttonBar);

	// Connect buttons
	connect(m_refreshButton, &QPushButton::clicked, this, &GamayunWidget::refreshMetadata);
	connect(m_pullSelected, &QPushButton::clicked, this, &GamayunWidget::pullSelectedLumina);
	connect(m_inspectPulled, &QPushButton::clicked, this, &GamayunWidget::inspectPulledSelected);
	connect(m_applyPulled, &QPushButton::clicked, this, &GamayunWidget::applyPulledToSelected);
	connect(m_pullAll, &QPushButton::clicked, this, &GamayunWidget::pullAllLumina);
	connect(m_applyPulledAll, &QPushButton::clicked, this, &GamayunWidget::applyPulledToAll);

	setLayout(layout);

	// Register for analysis completion event to compute function hashes for all functions
	if (m_data)
	{
		// Always register a completion callback - it will fire when current/next analysis completes
		BinaryNinja::LogInfo("[Lumina] Registering for analysis completion callback...");
		m_data->AddAnalysisCompletionEvent([this]() {
			if (!m_hasComputedInitialHashes)
			{
				m_hasComputedInitialHashes = true;
				computeFunctionHashesForAllFunctions();
			}
		});

		// Also check if initial analysis already completed (widget opened after analysis)
		if (m_data->HasInitialAnalysis() && !m_hasComputedInitialHashes)
		{
			BinaryNinja::LogInfo("[Lumina] Initial analysis already complete, computing function hashes...");
			m_hasComputedInitialHashes = true;
			computeFunctionHashesForAllFunctions();
		}
	}
}

void GamayunWidget::notifyViewChanged(ViewFrame* frame)
{
	const BinaryViewRef previousData = m_data;
	m_frame = frame;
	m_data = nullptr;
	if (frame)
	{
		// Update m_data from the current view in the frame
		auto view = frame->getCurrentViewInterface();
		if (view)
		{
			m_data = view->getData();
		}
	}
	if (previousData != m_data)
		m_hasComputedInitialHashes = false;
	m_pullCache.clear();

	// Refresh the model silently (without triggering Lumina extraction)
	if (m_table)
		m_table->setContext(m_frame, m_data);
	else if (m_model)
		m_model->setBinaryView(m_data);

	// Fallback: check if initial analysis completed and we haven't computed yet
	if (m_data && !m_hasComputedInitialHashes && m_data->HasInitialAnalysis())
	{
		BinaryNinja::LogInfo("[Lumina] Initial analysis detected in notifyViewChanged, computing function hashes...");
		m_hasComputedInitialHashes = true;
		computeFunctionHashesForAllFunctions();
	}
}

void GamayunWidget::notifyOffsetChanged(uint64_t offset)
{
	if (!m_data)
		return;

	// Find the function containing this offset
	auto funcs = m_data->GetAnalysisFunctionsContainingAddress(offset);
	if (funcs.empty())
		return;

	auto func = funcs[0];
	std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
	uint64_t funcStart = func->GetStart();

	// Compute function hash
	lumina::PatternResult pattern = lumina::computePattern(m_data, func);

	if (pattern.success)
	{
		// Format hash as hex string
		char hashStr[33];
		for (int i = 0; i < 16; i++)
		{
			snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
		}

		BinaryNinja::LogInfo("[Lumina] %s @ 0x%llx | Function Hash: %s | Size: %u bytes",
			funcName.c_str(),
			(unsigned long long)funcStart,
			hashStr,
			pattern.func_size);
	}
}

void GamayunWidget::notifyFontChanged()
{
	m_table->updateFont();
}

void GamayunWidget::computeFunctionHashesForAllFunctions()
{
	if (!m_data)
	{
		BinaryNinja::LogWarn("[Lumina] Cannot compute function hashes: no BinaryView");
		return;
	}

	auto functions = m_data->GetAnalysisFunctionList();
	if (functions.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No functions found in binary");
		return;
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Computing function hashes for %zu functions...", functions.size());
	BinaryNinja::LogInfo("[Lumina] ========================================");

	size_t success = 0;
	size_t failed = 0;

	for (auto& func : functions)
	{
		std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
		uint64_t funcStart = func->GetStart();

		lumina::PatternResult pattern = lumina::computePattern(m_data, func);

		if (pattern.success)
		{
			char hashStr[33];
			for (int i = 0; i < 16; i++)
			{
				snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
			}

			BinaryNinja::LogInfo("[Lumina] 0x%08llx | %s | %s | %u bytes",
				(unsigned long long)funcStart,
				hashStr,
				funcName.c_str(),
				pattern.func_size);
			success++;
		}
		else
		{
			BinaryNinja::LogWarn("[Lumina] 0x%08llx | FAILED: %s | %s",
				(unsigned long long)funcStart,
				pattern.error.c_str(),
				funcName.c_str());
			failed++;
		}
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Completed: %zu succeeded, %zu failed", success, failed);
	BinaryNinja::LogInfo("[Lumina] ========================================");
}

void GamayunWidget::refreshMetadata()
{
	if (m_model)
		m_model->refresh();
}

void GamayunWidget::setBusyState(bool busy)
{
	m_busy = busy;
	if (m_table)
		m_table->setEnabled(!busy);
	if (m_refreshButton)
		m_refreshButton->setEnabled(!busy);
	if (m_pullSelected)
		m_pullSelected->setEnabled(!busy);
	if (m_pullAll)
		m_pullAll->setEnabled(!busy);
	if (m_inspectPulled)
		m_inspectPulled->setEnabled(!busy);
	if (m_applyPulled)
		m_applyPulled->setEnabled(!busy);
	if (m_applyPulledAll)
		m_applyPulledAll->setEnabled(!busy);
}

bool GamayunWidget::ensureIdle(const QString& action)
{
	if (!m_busy)
		return true;

	QMessageBox::information(this, "Gamayun Busy", QString("Please wait for the current %1 task to finish.").arg(action));
	return false;
}

void GamayunWidget::pullSelectedLumina()
{
	if (!ensureIdle("Lumina"))
		return;
	if (!m_data) { QMessageBox::warning(this, "Lumina Pull", "No BinaryView"); return; }

	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina Pull", "No entries selected."); return; }

	std::vector<uint64_t> selectedAddresses;
	selectedAddresses.reserve(selected.size());
	for (auto* entry : selected)
		selectedAddresses.push_back(entry->address);

	QPointer<GamayunWidget> widget(this);
	BinaryViewRef data = m_data;
	auto task = BinaryNinja::Ref<BinaryNinja::BackgroundTask>(new BinaryNinja::BackgroundTask("Gamayun: Pulling selected Lumina metadata", false));
	setBusyState(true);

	std::thread([widget, task, data, selectedAddresses = std::move(selectedAddresses)]() mutable {
		PullResult result;
		try
		{
			auto functionsByAddress = buildFunctionMap(data);
			std::vector<std::array<uint8_t, 16>> hashes;
			std::vector<uint64_t> addrs;
			hashes.reserve(selectedAddresses.size());
			addrs.reserve(selectedAddresses.size());

			for (size_t i = 0; i < selectedAddresses.size(); ++i)
			{
				task->SetProgressText("Gamayun: Preparing selected Lumina queries");
				auto it = functionsByAddress.find(selectedAddresses[i]);
				if (it == functionsByAddress.end())
					continue;

				auto pullFilter = lumina::shouldSkipPull(data, it->second);
				if (pullFilter.shouldSkip)
				{
					result.skipped++;
					BinaryNinja::LogDebug("[Lumina] Pull filter: skipping %s - %s",
						it->second->GetSymbol() ? it->second->GetSymbol()->GetShortName().c_str() : "<unnamed>",
						pullFilter.reason.c_str());
					continue;
				}

				hashes.push_back(computeFunctionHash(data, it->second));
				addrs.push_back(selectedAddresses[i]);
			}

			result.requested = hashes.size();
			if (hashes.empty())
			{
				result.success = true;
			}
			else
			{
				task->SetProgressText("Gamayun: Fetching selected Lumina metadata");
				const auto hello = lumina::build_hello_request();
				const auto pull = lumina::build_pull_request(0, hashes);
				auto cli = lumina::createConfiguredClient(nullptr);
				std::vector<lumina::OperationResult> statuses;
				std::vector<lumina::PulledFunction> funcs;
				if (!cli->helloAndPull(hello, pull, &result.error, &statuses, &funcs, lumina::getTimeoutMs()))
				{
					result.success = false;
				}
				else
				{
					size_t fi = 0;
					for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i)
					{
						if (statuses[i] != lumina::OperationResult::Ok)
							continue;
						if (fi >= funcs.size())
							break;
						cachePulledFunction(result.cacheUpdates, addrs[i], funcs[fi++]);
						result.found++;
					}
					result.success = true;
				}
			}
		}
		catch (const std::exception& exception)
		{
			result.success = false;
			result.error = QString::fromStdString(exception.what());
		}

		BinaryNinja::ExecuteOnMainThread([widget, task, result = std::move(result)]() mutable {
			task->Finish();
			if (!widget)
				return;

			widget->setBusyState(false);
			if (!result.success)
			{
				QMessageBox::critical(widget, "Lumina Pull", QString("Failed: %1").arg(result.error));
				return;
			}

			for (auto& [addr, cache] : result.cacheUpdates)
				widget->m_pullCache[addr] = std::move(cache);

			if (widget->m_model)
				widget->m_model->notifyPullCacheChanged();

			QMessageBox::information(widget, "Lumina Pull",
				QString("Requested %1 function(s).\nFound %2; updated cache for selected rows.%3")
					.arg(result.requested)
					.arg(result.found)
					.arg(result.skipped > 0 ? QString("\nSkipped %1 function(s) due to the reliability filter.").arg(result.skipped) : QString()));
		});
	}).detach();
}

void GamayunWidget::pullAllLumina()
{
	if (!ensureIdle("Lumina"))
		return;
	if (!m_data) { QMessageBox::warning(this, "Lumina Pull All", "No BinaryView"); return; }

	auto functions = m_data->GetAnalysisFunctionList();
	if (functions.empty()) { QMessageBox::information(this, "Lumina Pull All", "No functions in binary."); return; }

	QPointer<GamayunWidget> widget(this);
	BinaryViewRef data = m_data;
	auto task = BinaryNinja::Ref<BinaryNinja::BackgroundTask>(new BinaryNinja::BackgroundTask("Gamayun: Pulling all Lumina metadata", false));
	setBusyState(true);

	std::thread([widget, task, data]() mutable {
		PullResult result;
		try
		{
			auto functions = data->GetAnalysisFunctionList();
			const char* debugEnv = std::getenv("LUMINA_DEBUG");
			bool debugMode = (debugEnv && *debugEnv == '1');

			std::vector<std::array<uint8_t, 16>> hashes;
			std::vector<uint64_t> addrs;
			std::vector<std::string> names;
			hashes.reserve(functions.size());
			addrs.reserve(functions.size());
			names.reserve(functions.size());

			for (size_t i = 0; i < functions.size(); ++i)
			{
				task->SetProgressText("Gamayun: Preparing Lumina queries for all functions");
				auto& func = functions[i];
				auto pullFilter = lumina::shouldSkipPull(data, func);
				if (pullFilter.shouldSkip)
				{
					result.skipped++;
					if (debugMode)
					{
						std::string name = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "<unnamed>";
						BinaryNinja::LogDebug("[Lumina] Pull filter: skipping %s - %s", name.c_str(), pullFilter.reason.c_str());
					}
					continue;
				}

				auto hash = computeFunctionHash(data, func);
				bool isZero = true;
				for (auto byte : hash)
				{
					if (byte != 0)
					{
						isZero = false;
						break;
					}
				}
				if (isZero)
					continue;

				hashes.push_back(hash);
				addrs.push_back(func->GetStart());
				names.push_back(func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>");
			}

			result.requested = hashes.size();
			if (result.skipped > 0)
				BinaryNinja::LogInfo("[Lumina] Pull filter: skipped %zu function(s)", result.skipped);

			if (hashes.empty())
			{
				result.success = true;
			}
			else
			{
				if (debugMode)
				{
					lumina::debug::dumpPullRequest("binja_pull_request.txt", hashes, addrs, names);
					BinaryNinja::LogInfo("[Lumina Debug] Dumped pull request to %s/binja_pull_request.txt",
						lumina::debug::getDebugDir().c_str());
				}

				BinaryNinja::LogInfo("[Lumina] Pull All: querying %zu functions...", hashes.size());
				task->SetProgressText("Gamayun: Fetching Lumina metadata for all functions");
				const auto hello = lumina::build_hello_request();
				const auto pull = lumina::build_pull_request(0, hashes);
				auto cli = lumina::createConfiguredClient(nullptr);
				std::vector<lumina::OperationResult> statuses;
				std::vector<lumina::PulledFunction> pulledFuncs;
				if (!cli->helloAndPull(hello, pull, &result.error, &statuses, &pulledFuncs, lumina::getTimeoutMs()))
				{
					result.success = false;
				}
				else
				{
					size_t fi = 0;
					for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i)
					{
						if (statuses[i] != lumina::OperationResult::Ok)
							continue;
						if (fi >= pulledFuncs.size())
							break;
						cachePulledFunction(result.cacheUpdates, addrs[i], pulledFuncs[fi++]);
						result.found++;
					}
					result.success = true;
				}
			}
		}
		catch (const std::exception& exception)
		{
			result.success = false;
			result.error = QString::fromStdString(exception.what());
		}

		BinaryNinja::ExecuteOnMainThread([widget, task, result = std::move(result)]() mutable {
			task->Finish();
			if (!widget)
				return;

			widget->setBusyState(false);
			if (!result.success)
			{
				QMessageBox::critical(widget, "Lumina Pull All", QString("Failed: %1").arg(result.error));
				return;
			}

			for (auto& [addr, cache] : result.cacheUpdates)
				widget->m_pullCache[addr] = std::move(cache);

			BinaryNinja::LogInfo("[Lumina] Pull All complete: %zu queried, %zu found", result.requested, result.found);
			if (widget->m_model)
				widget->m_model->notifyPullCacheChanged();

			QMessageBox::information(widget, "Lumina Pull All",
				QString("Queried %1 functions.\nFound metadata for %2.\nUse 'Apply' to apply changes.")
					.arg(result.requested)
					.arg(result.found));
		});
	}).detach();
}

void GamayunWidget::inspectPulledSelected()
{
	if (!m_data) {
		QMessageBox::warning(this, "Lumina Inspector", "No BinaryView");
		return;
	}

	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) {
		QMessageBox::information(this, "Lumina Inspector", "No entries selected.");
		return;
	}

	std::ostringstream report;
	size_t shown = 0;
	size_t missing = 0;
	for (auto* entry : selected)
	{
		auto it = m_pullCache.find(entry->address);
		if (it == m_pullCache.end() || !it->second.have) {
			missing++;
			continue;
		}

		if (shown != 0)
			report << "\n============================================================\n\n";
		report << lumina::formatPulledMetadataReport(entry->address, it->second);
		shown++;
	}

	if (shown == 0) {
		QMessageBox::information(
			this,
			"Lumina Inspector",
			QString("No pulled metadata in cache for the current selection (missing=%1).")
				.arg(missing));
		return;
	}

	if (missing > 0)
		report << "\n\nMissing cached entries: " << missing << "\n";

	showMetadataInspector(
		this,
		QString("Lumina Metadata Inspector (%1)").arg(shown),
		QString::fromStdString(report.str()));
}

void GamayunWidget::logPulledSelected()
{
	if (!m_data) {
		QMessageBox::warning(this, "Lumina Log Dump", "No BinaryView");
		return;
	}

	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) {
		QMessageBox::information(this, "Lumina Log Dump", "No entries selected.");
		return;
	}

	std::ostringstream report;
	size_t shown = 0;
	size_t missing = 0;
	for (auto* entry : selected)
	{
		auto it = m_pullCache.find(entry->address);
		if (it == m_pullCache.end() || !it->second.have) {
			missing++;
			continue;
		}

		if (shown != 0)
			report << "\n============================================================\n\n";
		report << lumina::formatPulledMetadataReport(entry->address, it->second);
		shown++;
	}

	if (shown == 0) {
		QMessageBox::information(
			this,
			"Lumina Log Dump",
			QString("No pulled metadata in cache for the current selection (missing=%1).")
				.arg(missing));
		return;
	}

	if (missing > 0)
		report << "\n\nMissing cached entries: " << missing << "\n";

	BinaryNinja::LogInfo("[Lumina] ===== Metadata Dump Start =====");
	BinaryNinja::LogInfo("%s", report.str().c_str());
	BinaryNinja::LogInfo("[Lumina] ===== Metadata Dump End =====");
	QMessageBox::information(
		this,
		"Lumina Log Dump",
		QString("Logged metadata for %1 function(s)%2.")
			.arg(shown)
			.arg(missing == 0 ? QString() : QString(" (%1 missing cache entries)").arg(missing)));
}

void GamayunWidget::applyPulledToSelected()
{
	if (!ensureIdle("apply"))
		return;
	if (!m_data) return;
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) {
		QMessageBox::information(this, "Apply Pulled", "No entries selected.");
		return;
	}

	std::vector<uint64_t> selectedAddresses;
	selectedAddresses.reserve(selected.size());
	for (auto* entry : selected)
		selectedAddresses.push_back(entry->address);

	QPointer<GamayunWidget> widget(this);
	BinaryViewRef data = m_data;
	auto pullCache = m_pullCache;
	auto task = BinaryNinja::Ref<BinaryNinja::BackgroundTask>(new BinaryNinja::BackgroundTask("Gamayun: Applying selected Lumina metadata", false));
	setBusyState(true);

	std::thread([widget, task, data, pullCache = std::move(pullCache), selectedAddresses = std::move(selectedAddresses)]() mutable {
		ApplyResult result;
		try
		{
			auto functionsByAddress = buildFunctionMap(data);
			for (size_t i = 0; i < selectedAddresses.size(); ++i)
			{
				task->SetProgressText("Gamayun: Applying selected Lumina metadata");
				auto cacheIt = pullCache.find(selectedAddresses[i]);
				if (cacheIt == pullCache.end() || !cacheIt->second.have)
				{
					result.missing++;
					continue;
				}

				auto funcIt = functionsByAddress.find(selectedAddresses[i]);
				if (funcIt == functionsByAddress.end())
				{
					result.missing++;
					continue;
				}

				if (lumina::applyMetadata(funcIt->second, cacheIt->second, result.stats))
					result.applied++;
			}
		}
		catch (const std::exception& exception)
		{
			BinaryNinja::LogError("[Lumina] Apply failed: %s", exception.what());
		}

		BinaryNinja::ExecuteOnMainThread([widget, task, result = std::move(result)]() mutable {
			task->Finish();
			if (!widget)
				return;

			widget->setBusyState(false);
			if (result.applied > 0)
				widget->refreshMetadata();

			const QString details = formatApplyStatsDetails(result.stats);
			QMessageBox::information(widget, "Apply Pulled",
				QString("Applied metadata to %1 function(s)%2; %3 missing cached data.")
					.arg(result.applied)
					.arg(details.isEmpty() ? "" : QString(" (%1)").arg(details))
					.arg(result.missing));
		});
	}).detach();
}

void GamayunWidget::applyPulledToAll()
{
	if (!ensureIdle("apply"))
		return;
	if (!m_data) return;

	if (m_pullCache.empty()) {
		QMessageBox::information(this, "Apply All", "No pulled data in cache. Pull functions first.");
		return;
	}

	QPointer<GamayunWidget> widget(this);
	BinaryViewRef data = m_data;
	auto pullCache = m_pullCache;
	auto task = BinaryNinja::Ref<BinaryNinja::BackgroundTask>(new BinaryNinja::BackgroundTask("Gamayun: Applying all Lumina metadata", false));
	setBusyState(true);

	std::thread([widget, task, data, pullCache = std::move(pullCache)]() mutable {
		ApplyResult result;
		try
		{
			auto functionsByAddress = buildFunctionMap(data);
			for (const auto& [addr, cache] : pullCache)
			{
				task->SetProgressText("Gamayun: Applying all Lumina metadata");
				if (!cache.have)
				{
					result.missing++;
					continue;
				}

				auto funcIt = functionsByAddress.find(addr);
				if (funcIt == functionsByAddress.end())
				{
					result.missing++;
					continue;
				}

				if (lumina::applyMetadata(funcIt->second, cache, result.stats))
					result.applied++;
			}
		}
		catch (const std::exception& exception)
		{
			BinaryNinja::LogError("[Lumina] Apply All failed: %s", exception.what());
		}

		BinaryNinja::ExecuteOnMainThread([widget, task, result = std::move(result)]() mutable {
			task->Finish();
			if (!widget)
				return;

			widget->setBusyState(false);
			if (result.applied > 0)
				widget->refreshMetadata();

			const QString details = formatApplyStatsDetails(result.stats);
			BinaryNinja::LogInfo(
				"[Lumina] Applied metadata to %zu functions (%zu names, %zu function comments, %zu function types, %zu address comments, %zu stack vars, %zu tags)",
				result.applied,
				result.stats.namesApplied,
				result.stats.functionCommentsApplied,
				result.stats.functionTypesApplied,
				result.stats.addressCommentsApplied,
				result.stats.stackVariablesApplied,
				result.stats.tagsApplied);

			QMessageBox::information(widget, "Apply All",
				QString("Applied Lumina metadata to %1 function(s)%2.")
					.arg(result.applied)
					.arg(details.isEmpty() ? "" : QString(" (%1)").arg(details)));
		});
	}).detach();
}

void GamayunWidget::batchDiffAndApplySelected()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina", "No BinaryView"); return; }
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina", "No entries selected."); return; }

	auto functionsByAddress = buildFunctionMap(m_data);

	// Build rows from cache + local
	std::vector<LuminaBulkDiffRow> rows;
	rows.reserve(selected.size());

	size_t missing = 0;
	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = functionsByAddress.find(e->address);
		if (fit == functionsByAddress.end()) { missing++; continue; }

		FunctionRef func = fit->second;
		LuminaBulkDiffRow row;
		row.address = e->address;
		row.localName = QString::fromStdString(func->GetSymbol() ? func->GetSymbol()->GetFullName() : std::string("<unnamed>"));
		row.remoteName = QString::fromStdString(cit->second.remoteName);
		row.localComment = QString::fromStdString(func->GetComment());
		row.remoteComment = QString::fromStdString(lumina::buildMergedFunctionComment(cit->second.metadata));

		// default: check only when different
		row.applyComment  = (row.localComment != row.remoteComment);
		rows.push_back(std::move(row));
	}

	if (rows.empty()) {
		QMessageBox::information(this, "Lumina",
			QString("No cached pulled data for selected rows (missing=%1).").arg(missing));
		return;
	}

	LuminaBulkDiffDialog dlg(this, std::move(rows));
	if (dlg.exec() != QDialog::Accepted) return;

	// Apply selections
	const auto& outRows = dlg.rows();
	size_t applied = 0;
	for (const auto& r : outRows) {
		auto fit = functionsByAddress.find(r.address);
		if (fit == functionsByAddress.end()) continue;
		FunctionRef func = fit->second;

		bool changed = false;
		if (r.applyComment && (r.localComment != r.remoteComment)) {
			func->SetComment(r.remoteComment.toStdString());
			changed = true;
		}
		if (changed) applied++;
	}

	QMessageBox::information(this, "Lumina",
		QString("Applied changes to %1 function(s). Missing cache: %2").arg(applied).arg(missing));
}

// GamayunWidgetType implementation
GamayunWidgetType::GamayunWidgetType()
	: SidebarWidgetType(makeGamayunSidebarIcon(), "Gamayun")
{
}

SidebarWidget* GamayunWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new GamayunWidget(frame, data);
}
