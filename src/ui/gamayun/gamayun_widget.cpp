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
#include <QGridLayout>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <utility>

namespace {

std::array<uint8_t, 16> computeCalcRelHash(BinaryViewRef view, FunctionRef func)
{
	return lumina::computeCalcRelHash(view, func);
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

}  // namespace

// GamayunWidget implementation
GamayunWidget::GamayunWidget(ViewFrame* frame, BinaryViewRef data)
	: SidebarWidget("Gamayun"), m_data(data), m_frame(frame)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(4);

	// Create table
	m_table = new GamayunTableView(this, frame, data);
	m_model = static_cast<GamayunModel*>(m_table->model());
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

	// Register for analysis completion event to compute CalcRel for all functions
	if (m_data)
	{
		// Always register a completion callback - it will fire when current/next analysis completes
		BinaryNinja::LogInfo("[Lumina] Registering for analysis completion callback...");
		m_data->AddAnalysisCompletionEvent([this]() {
			if (!m_hasComputedInitialCalcRel)
			{
				m_hasComputedInitialCalcRel = true;
				computeCalcRelForAllFunctions();
			}
		});

		// Also check if initial analysis already completed (widget opened after analysis)
		if (m_data->HasInitialAnalysis() && !m_hasComputedInitialCalcRel)
		{
			BinaryNinja::LogInfo("[Lumina] Initial analysis already complete, computing CalcRel...");
			m_hasComputedInitialCalcRel = true;
			computeCalcRelForAllFunctions();
		}
	}
}

void GamayunWidget::notifyViewChanged(ViewFrame* frame)
{
	m_frame = frame;
	if (frame)
	{
		// Update m_data from the current view in the frame
		auto view = frame->getCurrentViewInterface();
		if (view)
		{
			m_data = view->getData();
		}
	}

	// Refresh the model silently (without triggering Lumina extraction)
	if (m_model && m_data)
		m_model->refresh();

	// Fallback: check if initial analysis completed and we haven't computed yet
	if (m_data && !m_hasComputedInitialCalcRel && m_data->HasInitialAnalysis())
	{
		BinaryNinja::LogInfo("[Lumina] Initial analysis detected in notifyViewChanged, computing CalcRel...");
		m_hasComputedInitialCalcRel = true;
		computeCalcRelForAllFunctions();
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

	// Compute CalcRel hash
	lumina::PatternResult pattern = lumina::computePattern(m_data, func);

	if (pattern.success)
	{
		// Format hash as hex string
		char hashStr[33];
		for (int i = 0; i < 16; i++)
		{
			snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
		}

		BinaryNinja::LogInfo("[Lumina] %s @ 0x%llx | CalcRel: %s | Size: %u bytes",
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

void GamayunWidget::computeCalcRelForAllFunctions()
{
	if (!m_data)
	{
		BinaryNinja::LogWarn("[Lumina] Cannot compute CalcRel: no BinaryView");
		return;
	}

	auto functions = m_data->GetAnalysisFunctionList();
	if (functions.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No functions found in binary");
		return;
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Computing CalcRel for %zu functions...", functions.size());
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

void GamayunWidget::pullSelectedLumina()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina Pull", "No BinaryView"); return; }

	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina Pull", "No entries selected."); return; }

	auto functionsByAddress = buildFunctionMap(m_data);

	// Build hash list in the same order as 'selected'
	std::vector<std::array<uint8_t,16>> hashes;
	std::vector<uint64_t> addrs;
	size_t skippedCount = 0;
	hashes.reserve(selected.size());
	addrs.reserve(selected.size());
	for (auto* e : selected) {
		auto it = functionsByAddress.find(e->address);
		if (it == functionsByAddress.end()) continue;
		auto pullFilter = lumina::shouldSkipPull(m_data, it->second);
		if (pullFilter.shouldSkip) {
			skippedCount++;
			BinaryNinja::LogDebug("[Lumina] Pull filter: skipping %s - %s",
				it->second->GetSymbol() ? it->second->GetSymbol()->GetShortName().c_str() : "<unnamed>",
				pullFilter.reason.c_str());
			continue;
		}
		hashes.push_back(computeCalcRelHash(m_data, it->second));
		addrs.push_back(e->address);
	}
	if (hashes.empty()) { QMessageBox::information(this, "Lumina Pull", "No functions resolved."); return; }

	const auto hello = lumina::build_hello_request();
	const auto pull = lumina::build_pull_request(0, hashes);

	auto cli = lumina::createConfiguredClient(this);
	QString err;
	std::vector<lumina::OperationResult> statuses;
	std::vector<lumina::PulledFunction> funcs;
	if (!cli->helloAndPull(hello, pull, &err, &statuses, &funcs, lumina::getTimeoutMs())) {
		QMessageBox::critical(this, "Lumina Pull", QString("Failed: %1").arg(err));
		return;
	}

	// Map results: statuses length == queries; funcs contains only found entries in order
	size_t fi = 0, found = 0;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i) {
		if (statuses[i] == lumina::OperationResult::Ok) {
			if (fi >= funcs.size()) break;
			cachePulledFunction(m_pullCache, addrs[i], funcs[fi++]);
			found++;
		}
	}

	QMessageBox::information(this, "Lumina Pull",
		QString("Requested %1 function(s).\nFound %2; updated cache for selected rows.%3")
			.arg(hashes.size())
			.arg(found)
			.arg(skippedCount > 0 ? QString("\nSkipped %1 function(s) due to the reliability filter.").arg(skippedCount) : QString()));
}

void GamayunWidget::pullAllLumina()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina Pull All", "No BinaryView"); return; }

	auto functions = m_data->GetAnalysisFunctionList();
	if (functions.empty()) { QMessageBox::information(this, "Lumina Pull All", "No functions in binary."); return; }

	// Check if debug mode is enabled
	const char* debugEnv = std::getenv("LUMINA_DEBUG");
	bool debugMode = (debugEnv && *debugEnv == '1');

	// Build hash list for ALL functions in the binary
	std::vector<std::array<uint8_t,16>> hashes;
	std::vector<uint64_t> addrs;
	std::vector<std::string> names;
	std::vector<FunctionRef> funcRefs;
	hashes.reserve(functions.size());
	addrs.reserve(functions.size());
	names.reserve(functions.size());
	funcRefs.reserve(functions.size());

	size_t skippedCount = 0;
	for (auto& func : functions) {
		// Apply pull filter to skip functions unlikely to produce reliable hashes
		auto pullFilter = lumina::shouldSkipPull(m_data, func);
		if (pullFilter.shouldSkip) {
			skippedCount++;
			if (debugMode) {
				std::string name = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "<unnamed>";
				BinaryNinja::LogDebug("[Lumina] Pull filter: skipping %s - %s", name.c_str(), pullFilter.reason.c_str());
			}
			continue;
		}

		auto hash = computeCalcRelHash(m_data, func);
		// Skip zero hashes (failed pattern generation)
		bool isZero = true;
		for (auto b : hash) { if (b != 0) { isZero = false; break; } }
		if (isZero) continue;

		hashes.push_back(hash);
		addrs.push_back(func->GetStart());
		std::string name = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
		names.push_back(name);
		funcRefs.push_back(func);
	}

	if (skippedCount > 0) {
		BinaryNinja::LogInfo("[Lumina] Pull filter: skipped %zu function(s)", skippedCount);
	}

	if (hashes.empty()) { QMessageBox::information(this, "Lumina Pull All", "No valid function hashes."); return; }

	// Dump debug info if enabled
	if (debugMode) {
		lumina::debug::dumpPullRequest("binja_pull_request.txt", hashes, addrs, names);
		BinaryNinja::LogInfo("[Lumina Debug] Dumped pull request to %s/binja_pull_request.txt",
			lumina::debug::getDebugDir().c_str());
	}

	BinaryNinja::LogInfo("[Lumina] Pull All: querying %zu functions...", hashes.size());

	const auto hello = lumina::build_hello_request();
	const auto pull = lumina::build_pull_request(0, hashes);

	auto cli = lumina::createConfiguredClient(this);
	QString err;
	std::vector<lumina::OperationResult> statuses;
	std::vector<lumina::PulledFunction> pulledFuncs;

	int timeout = lumina::getTimeoutMs();
	if (!cli->helloAndPull(hello, pull, &err, &statuses, &pulledFuncs, timeout)) {
		QMessageBox::critical(this, "Lumina Pull All", QString("Failed: %1").arg(err));
		return;
	}

	// Map results to cache
	size_t fi = 0, found = 0;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i) {
		if (statuses[i] == lumina::OperationResult::Ok) {
			if (fi >= pulledFuncs.size()) break;
			cachePulledFunction(m_pullCache, addrs[i], pulledFuncs[fi++]);
			found++;
		}
	}

	BinaryNinja::LogInfo("[Lumina] Pull All complete: %zu queried, %zu found", hashes.size(), found);
	QMessageBox::information(this, "Lumina Pull All",
		QString("Queried %1 functions.\nFound metadata for %2.\nUse 'Apply' to apply changes.")
			.arg(hashes.size()).arg(found));
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
	if (!m_data) return;
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) {
		QMessageBox::information(this, "Apply Pulled", "No entries selected.");
		return;
	}

	auto functionsByAddress = buildFunctionMap(m_data);

	size_t applied = 0, missing = 0;
	lumina::ApplyStats stats;

	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = functionsByAddress.find(e->address);
		if (fit == functionsByAddress.end()) { missing++; continue; }

		if (lumina::applyMetadata(fit->second, cit->second, stats)) {
			applied++;
		}
	}

	// Refresh the table to show updated names
	if (applied > 0) {
		refreshMetadata();
	}

	const QString details = formatApplyStatsDetails(stats);

	QMessageBox::information(this, "Apply Pulled",
		QString("Applied metadata to %1 function(s)%2; %3 missing cached data.")
			.arg(applied)
			.arg(details.isEmpty() ? "" : QString(" (%1)").arg(details))
			.arg(missing));
}

void GamayunWidget::applyPulledToAll()
{
	if (!m_data) return;

	if (m_pullCache.empty()) {
		QMessageBox::information(this, "Apply All", "No pulled data in cache. Pull functions first.");
		return;
	}

	auto functionsByAddress = buildFunctionMap(m_data);

	size_t applied = 0, skipped = 0;
	lumina::ApplyStats stats;

	for (const auto& [addr, cache] : m_pullCache) {
		if (!cache.have) { skipped++; continue; }
		auto fit = functionsByAddress.find(addr);
		if (fit == functionsByAddress.end()) { skipped++; continue; }

		if (lumina::applyMetadata(fit->second, cache, stats)) {
			applied++;
		}
	}

	// Refresh the table to show updated names
	if (applied > 0) {
		refreshMetadata();
	}

	const QString details = formatApplyStatsDetails(stats);

	BinaryNinja::LogInfo(
		"[Lumina] Applied metadata to %zu functions (%zu names, %zu function comments, %zu function types, %zu address comments, %zu stack vars, %zu tags)",
		applied,
		stats.namesApplied,
		stats.functionCommentsApplied,
		stats.functionTypesApplied,
		stats.addressCommentsApplied,
		stats.stackVariablesApplied,
		stats.tagsApplied);

	QMessageBox::information(this, "Apply All",
		QString("Applied Lumina metadata to %1 function(s)%2.")
			.arg(applied)
			.arg(details.isEmpty() ? "" : QString(" (%1)").arg(details)));
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
	: SidebarWidgetType(QImage(), "Gamayun")
{
}

SidebarWidget* GamayunWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new GamayunWidget(frame, data);
}
