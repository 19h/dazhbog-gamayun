#include "metadatasidebar.h"
#include "pattern_gen.h"
#include "lumina_settings.h"
#include "debug_dump.h"
// Forward declaration for View class
class View;
#include <QMessageBox>
#include <QHeaderView>
#include <QCryptographicHash>
#include <QProcessEnvironment>
#include <QSysInfo>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

// Forward declaration
void extractAndLogLuminaMetadata(BinaryViewRef data, ViewFrame* frame = nullptr);

/**
 * Encode a function for Lumina using the CalcRel hash algorithm.
 *
 * This computes a position-independent hash by normalizing instruction bytes:
 *   normalized_byte = raw_byte & ~mask_byte
 *
 * Where mask_byte indicates position-dependent data (addresses, offsets).
 */
static lumina::EncodedFunction encodeOneFunction(BinaryViewRef bv, FunctionRef func) {
	lumina::EncodedFunction ef;
	ef.name = func->GetSymbol() ? func->GetSymbol()->GetFullName() : std::string("<unnamed>");

	// Compute CalcRel hash using architecture-aware pattern generation
	lumina::PatternResult pattern = lumina::computePattern(bv, func);

	if (pattern.success) {
		ef.hash = pattern.hash;
		ef.func_len = pattern.func_size;
	} else {
		// Fallback: zero hash and estimate size from basic blocks
		ef.hash = std::array<uint8_t, 16>{};
		auto blocks = func->GetBasicBlocks();
		uint32_t size = 0;
		for (auto& b : blocks) {
			size += static_cast<uint32_t>(b->GetEnd() - b->GetStart());
		}
		ef.func_len = size;
		BinaryNinja::LogWarn("Pattern generation failed for %s: %s",
			ef.name.c_str(), pattern.error.c_str());
	}

	// TLV payload: no-return flag, comment, variable names
	const bool noReturn = !func->CanReturn();
	const std::string comment = func->GetComment();
	std::vector<std::string> varNames;
	auto vars = func->GetVariables();
	varNames.reserve(vars.size());
	for (auto& vPair : vars) varNames.push_back(vPair.second.name);
	ef.func_data = lumina::build_function_tlv(noReturn, comment, varNames);

	ef.unk2 = 0;
	return ef;
}

static std::array<uint8_t,16> md5_zero() {
	std::array<uint8_t,16> z{}; return z;
}

/**
 * Compute the 16-byte CalcRel hash for a function.
 *
 * Uses Lumina's normalization algorithm to produce a position-independent
 * function signature that matches the same function at different addresses.
 */
static std::array<uint8_t,16> compute_key(BinaryViewRef bv, FunctionRef func) {
	return lumina::computeCalcRelHash(bv, func);
}

// FunctionMetadataModel implementation
FunctionMetadataModel::FunctionMetadataModel(QWidget* parent, BinaryViewRef data)
	: QAbstractTableModel(parent), m_data(data)
{
	refresh();
}

void FunctionMetadataModel::refresh()
{
	beginResetModel();
	m_entries.clear();
	
	if (!m_data)
	{
		endResetModel();
		return;
	}

	// Get all functions
	auto functions = m_data->GetAnalysisFunctionList();
	
	for (auto& func : functions)
	{
		FunctionMetadataEntry entry;
		entry.address = func->GetStart();
		auto sym = func->GetSymbol();
		entry.name = QString::fromStdString(sym ? sym->GetFullName() : "<unnamed>");

		// Check for function comment
		bool hasMetadata = false;
		std::string comment = func->GetComment();
		if (!comment.empty())
		{
			entry.metadata[QString("comment")] = QString::fromStdString(comment);
			hasMetadata = true;
		}

		// Check for no-return attribute
		if (!func->CanReturn())
		{
			entry.metadata[QString("no_return")] = QString("true");
			hasMetadata = true;
		}

		// Always add entries for demonstration, even without metadata
		// In a real implementation, you might only add functions with metadata
		if (hasMetadata || functions.size() < 50) // Limit display for large binaries
		{
			m_entries.push_back(entry);
		}
	}
	
	endResetModel();
}

int FunctionMetadataModel::columnCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return 4; // Checkbox, Address, Name, Metadata Keys
}

int FunctionMetadataModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return m_entries.size();
}

QVariant FunctionMetadataModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return QVariant();
	
	const auto& entry = m_entries[index.row()];
	
	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case 0: // Checkbox column - no display text
			return QVariant();
		case 1: // Address
			return QString("0x%1").arg(entry.address, 0, 16);
		case 2: // Name
			return entry.name;
		case 3: // Metadata keys
			{
				QStringList keys;
				for (auto it = entry.metadata.begin(); it != entry.metadata.end(); ++it)
					keys << it->first;
				return keys.join(", ");
			}
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == 0)
	{
		return entry.selected ? Qt::Checked : Qt::Unchecked;
	}
	else if (role == Qt::TextAlignmentRole && index.column() == 1)
	{
		return QVariant(Qt::AlignRight | Qt::AlignVCenter);
	}
	
	return QVariant();
}

QVariant FunctionMetadataModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch (section)
		{
		case 0: return "✓";
		case 1: return "Address";
		case 2: return "Function Name";
		case 3: return "Metadata";
		}
	}
	return QVariant();
}

Qt::ItemFlags FunctionMetadataModel::flags(const QModelIndex& index) const
{
	if (!index.isValid())
		return Qt::NoItemFlags;
	
	Qt::ItemFlags flags = QAbstractTableModel::flags(index);
	
	if (index.column() == 0)
		flags |= Qt::ItemIsUserCheckable;
	
	return flags;
}

bool FunctionMetadataModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return false;
	
	if (role == Qt::CheckStateRole && index.column() == 0)
	{
		m_entries[index.row()].selected = (value.toInt() == Qt::Checked);
		emit dataChanged(index, index);
		return true;
	}
	
	return false;
}

void FunctionMetadataModel::selectAll()
{
	for (auto& entry : m_entries)
		entry.selected = true;
	if (!m_entries.empty())
		emit dataChanged(createIndex(0, 0), createIndex(int(m_entries.size()) - 1, 0));
}

void FunctionMetadataModel::selectNone()
{
	for (auto& entry : m_entries)
		entry.selected = false;
	if (!m_entries.empty())
		emit dataChanged(createIndex(0, 0), createIndex(int(m_entries.size()) - 1, 0));
}

std::vector<FunctionMetadataEntry*> FunctionMetadataModel::getSelectedEntries()
{
	std::vector<FunctionMetadataEntry*> selected;
	for (auto& entry : m_entries)
	{
		if (entry.selected)
			selected.push_back(&entry);
	}
	return selected;
}

// FunctionMetadataTableView implementation
FunctionMetadataTableView::FunctionMetadataTableView(QWidget* parent, ViewFrame* frame, BinaryViewRef data)
	: QTableView(parent), m_data(data), m_frame(frame)
{
	m_model = new FunctionMetadataModel(this, data);
	setModel(m_model);
	
	// Configure table appearance
	horizontalHeader()->setStretchLastSection(true);
	horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
	verticalHeader()->setVisible(false);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);
	setSortingEnabled(false);
	setAlternatingRowColors(true);
	
	// Set column widths
	setColumnWidth(0, 30);  // Checkbox
	setColumnWidth(1, 100); // Address
	setColumnWidth(2, 200); // Name
	
	updateFont();

	connect(this, &QTableView::doubleClicked, this, &FunctionMetadataTableView::onRowDoubleClicked);

	// Connect clicked signal to print CalcRel hash when a row is clicked
	connect(this, &QTableView::clicked, this, &FunctionMetadataTableView::onRowClicked);
}

void FunctionMetadataTableView::updateFont()
{
	setFont(getMonospaceFont(this));
}

void FunctionMetadataTableView::contextMenuEvent(QContextMenuEvent* event)
{
	QMenu menu(this);
	
	QModelIndex index = indexAt(event->pos());
	if (index.isValid())
	{
		menu.addAction("Navigate to Function", this, &FunctionMetadataTableView::navigateToFunction);
		menu.addAction("Apply Metadata", this, &FunctionMetadataTableView::applyMetadataToSelected);
		menu.addSeparator();
		// Push Selected
		menu.addAction("Push Selected (Lumina)", [this]() {
			auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
			if (p) p->pushSelectedLumina();
		});
	}
	
	menu.addAction("Refresh", [this]() { m_model->refresh(); });
	menu.addAction("Select All", [this]() { m_model->selectAll(); });
	menu.addAction("Select None", [this]() { m_model->selectNone(); });
	
	// Lumina operations
	menu.addSeparator();
	menu.addAction("Push All (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pushAllLumina();
	});
	menu.addSeparator();
	menu.addAction("Pull Selected (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pullSelectedLumina();
	});
	menu.addAction("Pull All (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pullAllLumina();
	});
	menu.addAction("Apply Pulled to Selected", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->applyPulledToSelected();
	});
	menu.addAction("Batch Diff & Apply (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->batchDiffAndApplySelected();
	});
	
	menu.exec(event->globalPos());
}

void FunctionMetadataTableView::onRowDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || !m_frame || !m_data)
		return;

	const auto& entry = m_model->entryAt(index.row());

	// Navigate to the function address
	m_frame->navigate(m_data, entry.address);
}

void FunctionMetadataTableView::onRowClicked(const QModelIndex& index)
{
	if (!index.isValid() || !m_data)
		return;

	const auto& entry = m_model->entryAt(index.row());

	// Find the function at this address
	auto func = m_data->GetAnalysisFunction(m_data->GetDefaultPlatform(), entry.address);
	if (!func)
	{
		// Try getting any function that starts at this address
		auto funcs = m_data->GetAnalysisFunctionsForAddress(entry.address);
		if (!funcs.empty())
			func = funcs[0];
	}

	if (!func)
		return;

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

		// Show in status bar - this is always visible
		QString msg = QString("[Lumina] %1 @ 0x%2 | CalcRel: %3")
			.arg(QString::fromStdString(entry.name.toStdString()))
			.arg(entry.address, 0, 16)
			.arg(QString::fromLatin1(hashStr));

		// Use LogAlert for visibility - shows in log with alert icon
		BinaryNinja::LogAlert("[Lumina] %s @ 0x%llx | CalcRel: %s | Size: %u bytes",
			entry.name.toStdString().c_str(),
			(unsigned long long)entry.address,
			hashStr,
			pattern.func_size);
	}
}

void FunctionMetadataTableView::applyMetadataToSelected()
{
	QModelIndex index = currentIndex();
	if (!index.isValid())
		return;
	
	const auto& entry = m_model->entryAt(index.row());
	
	QString metadataInfo;
	for (auto it = entry.metadata.begin(); it != entry.metadata.end(); ++it)
	{
		metadataInfo += QString("%1: %2\n").arg(it->first, it->second);
	}
	
	QMessageBox::information(this, "Function Metadata",
		QString("Function: %1\nAddress: 0x%2\n\nMetadata:\n%3")
			.arg(entry.name)
			.arg(entry.address, 0, 16)
			.arg(metadataInfo.isEmpty() ? "No metadata" : metadataInfo));
}

void FunctionMetadataTableView::navigateToFunction()
{
	QModelIndex index = currentIndex();
	if (index.isValid())
		onRowDoubleClicked(index);
}

// FunctionMetadataSidebarWidget implementation
FunctionMetadataSidebarWidget::FunctionMetadataSidebarWidget(ViewFrame* frame, BinaryViewRef data)
	: SidebarWidget("Function Metadata"), m_data(data), m_frame(frame)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(4, 4, 4, 4);
	layout->setSpacing(4);

	// Create table
	m_table = new FunctionMetadataTableView(this, frame, data);
	m_model = static_cast<FunctionMetadataModel*>(m_table->model());
	layout->addWidget(m_table, 1);

	// Create compact button bar with just essential buttons
	QWidget* buttonBar = new QWidget(this);
	QGridLayout* buttonLayout = new QGridLayout(buttonBar);
	buttonLayout->setContentsMargins(0, 4, 0, 0);
	buttonLayout->setSpacing(4);

	m_refreshButton = new QPushButton("Refresh", buttonBar);
	m_pullSelected = new QPushButton("Pull", buttonBar);
	m_pushSelected = new QPushButton("Push", buttonBar);
	m_applyPulled = new QPushButton("Apply", buttonBar);
	m_pullAll = new QPushButton("Pull All", buttonBar);
	m_pushAll = new QPushButton("Push All", buttonBar);
	m_applyPulledAll = new QPushButton("Apply All", buttonBar);

	// Row 0: Main actions for selected
	buttonLayout->addWidget(m_refreshButton, 0, 0);
	buttonLayout->addWidget(m_pullSelected, 0, 1);
	buttonLayout->addWidget(m_pushSelected, 0, 2);
	buttonLayout->addWidget(m_applyPulled, 0, 3);

	// Row 1: Bulk actions for all functions
	buttonLayout->addWidget(m_pullAll, 1, 1);
	buttonLayout->addWidget(m_pushAll, 1, 2);
	buttonLayout->addWidget(m_applyPulledAll, 1, 3);

	layout->addWidget(buttonBar);

	// Connect buttons
	connect(m_refreshButton, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::refreshMetadata);
	connect(m_pullSelected, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pullSelectedLumina);
	connect(m_pushSelected, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pushSelectedLumina);
	connect(m_applyPulled, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::applyPulledToSelected);
	connect(m_pullAll, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pullAllLumina);
	connect(m_pushAll, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pushAllLumina);
	connect(m_applyPulledAll, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::applyPulledToAll);

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

		// Also check if initial analysis already completed (sidebar opened after analysis)
		if (m_data->HasInitialAnalysis() && !m_hasComputedInitialCalcRel)
		{
			BinaryNinja::LogInfo("[Lumina] Initial analysis already complete, computing CalcRel...");
			m_hasComputedInitialCalcRel = true;
			computeCalcRelForAllFunctions();
		}
	}
}

void FunctionMetadataSidebarWidget::notifyViewChanged(ViewFrame* frame)
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

void FunctionMetadataSidebarWidget::notifyOffsetChanged(uint64_t offset)
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

void FunctionMetadataSidebarWidget::notifyFontChanged()
{
	m_table->updateFont();
}

void FunctionMetadataSidebarWidget::computeCalcRelForAllFunctions()
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

void FunctionMetadataSidebarWidget::refreshMetadata()
{
	if (m_model)
		m_model->refresh();
	
	// LUMINA EXTRACTION: Extract and log metadata for current function when Refresh is clicked
	if (m_data)
	{
		BinaryNinja::LogInfo(">>> Refresh button clicked - extracting Lumina metadata...");
		extractAndLogLuminaMetadata(m_data, m_frame);
	}
}

void FunctionMetadataSidebarWidget::rejectAll()
{
	m_model->selectNone();
	QMessageBox::information(this, "Reject All", "All metadata entries deselected.");
}

void FunctionMetadataSidebarWidget::applySelected()
{
	auto selected = m_model->getSelectedEntries();
	
	if (selected.empty())
	{
		QMessageBox::information(this, "Apply Selected", "No entries selected.");
		return;
	}
	
	QString message = QString("Would apply metadata to %1 selected function(s):\n\n").arg(selected.size());
	
	int count = 0;
	for (auto* entry : selected)
	{
		message += QString("• %1 (0x%2)\n").arg(entry->name).arg(entry->address, 0, 16);
		if (++count >= 10)
		{
			message += QString("... and %1 more\n").arg(selected.size() - 10);
			break;
		}
	}
	
	QMessageBox::information(this, "Apply Selected", message);
}

void FunctionMetadataSidebarWidget::applyAll()
{
	int total = m_model->rowCount();
	
	QString message = QString("Would apply metadata to all %1 function(s) in the table.").arg(total);
	QMessageBox::information(this, "Apply All", message);
}

void FunctionMetadataSidebarWidget::pushSelectedLumina()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina Push", "No BinaryView"); return; }
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina Push", "No entries selected."); return; }

	// Map address -> FunctionRef
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	std::vector<lumina::EncodedFunction> funcs;
	funcs.reserve(selected.size());
	size_t skippedCount = 0;
	std::vector<std::string> skippedNames;

	for (auto* e : selected) {
		auto it = fbyAddr.find(e->address);
		if (it == fbyAddr.end()) continue;

		// Check if this function should be skipped to prevent Lumina pollution
		lumina::PushFilterResult filter = lumina::shouldSkipPush(m_data, it->second);
		if (filter.shouldSkip) {
			skippedCount++;
			std::string funcName = it->second->GetSymbol()
				? it->second->GetSymbol()->GetShortName()
				: "<unnamed>";
			skippedNames.push_back(funcName);
			BinaryNinja::LogWarn("[Lumina] Skipping push for %s: %s (size=%zu, movabs=%d)",
				funcName.c_str(), filter.reason.c_str(),
				filter.funcSize, filter.movabsCount);
			continue;
		}

		funcs.push_back(encodeOneFunction(m_data, it->second));
	}

	if (funcs.empty()) {
		QString msg = "No functions to push.";
		if (skippedCount > 0) {
			msg += QString("\n\n%1 function(s) were skipped to prevent Lumina pollution:\n").arg(skippedCount);
			for (size_t i = 0; i < std::min(skippedNames.size(), (size_t)5); i++) {
				msg += QString("  - %1\n").arg(QString::fromStdString(skippedNames[i]));
			}
			if (skippedNames.size() > 5) {
				msg += QString("  ... and %1 more\n").arg(skippedNames.size() - 5);
			}
			msg += "\n(Functions with size > 4500 bytes or > 4 movabs instructions are filtered)";
		}
		QMessageBox::information(this, "Lumina Push", msg);
		return;
	}

	// Build legacy Hello + PushMetadata payloads
	auto hello = lumina::encode_hello_payload(5);
	std::string idbPath = "<bn>";
	std::string filePath = "<unknown>";
	std::string hostName = QSysInfo::machineHostName().toStdString();
	auto push = lumina::encode_push_payload(/*unk0=*/1, idbPath, filePath, md5_zero(), hostName, funcs, {});  // unk0=1 to match IDA

	// Resolve server from env or defaults
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	QString host = env.contains("BN_LUMINA_HOST") ? env.value("BN_LUMINA_HOST") : QStringLiteral("127.0.0.1");
	quint16 port = env.contains("BN_LUMINA_PORT") ? env.value("BN_LUMINA_PORT").toUShort() : 20667;

	lumina::Client cli(host, port, this);
	QString err;
	std::vector<uint32_t> statuses;
	if (!cli.helloAndPush(hello, push, &err, &statuses, 8000)) {
		QMessageBox::critical(this, "Lumina Push", QString("Failed: %1").arg(err));
		return;
	}

	// Report: 1=new unique, 0=updated (per your server)
	size_t news = 0, updates = 0;
	for (uint32_t s : statuses) (s > 0 ? news : updates)++;

	QString msg = QString("Pushed %1 function(s): %2 new, %3 updated")
		.arg(statuses.size()).arg(news).arg(updates);
	if (skippedCount > 0) {
		msg += QString("\n\n%1 function(s) were skipped (likely incorrect hash):").arg(skippedCount);
		for (size_t i = 0; i < std::min(skippedNames.size(), (size_t)3); i++) {
			msg += QString("\n  - %1").arg(QString::fromStdString(skippedNames[i]));
		}
		if (skippedNames.size() > 3) {
			msg += QString("\n  ... and %1 more").arg(skippedNames.size() - 3);
		}
	}
	QMessageBox::information(this, "Lumina Push", msg);
}

void FunctionMetadataSidebarWidget::pushAllLumina()
{
	// Select all rows, reuse pushSelectedLumina
	m_model->selectAll();
	pushSelectedLumina();
}

void FunctionMetadataSidebarWidget::pullSelectedLumina()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina Pull", "No BinaryView"); return; }

	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina Pull", "No entries selected."); return; }

	// Map function start -> FunctionRef
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	// Build hash list in the same order as 'selected'
	std::vector<std::array<uint8_t,16>> hashes;
	std::vector<uint64_t> addrs;
	hashes.reserve(selected.size());
	addrs.reserve(selected.size());
	for (auto* e : selected) {
		auto it = fbyAddr.find(e->address);
		if (it == fbyAddr.end()) continue;
		hashes.push_back(compute_key(m_data, it->second));
		addrs.push_back(e->address);
	}
	if (hashes.empty()) { QMessageBox::information(this, "Lumina Pull", "No functions resolved."); return; }

	// Build request
	auto hello = lumina::encode_hello_payload(5);
	auto pull = lumina::encode_pull_payload(1, hashes);  // unk0=1 to match IDA

	// Resolve server (env or default)
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	QString host = env.contains("BN_LUMINA_HOST") ? env.value("BN_LUMINA_HOST") : QStringLiteral("127.0.0.1");
	quint16 port = env.contains("BN_LUMINA_PORT") ? env.value("BN_LUMINA_PORT").toUShort() : 20667;

	lumina::Client cli(host, port, this);
	QString err;
	std::vector<uint32_t> statuses;
	std::vector<lumina::PulledFunction> funcs;
	if (!cli.helloAndPull(hello, pull, &err, &statuses, &funcs, 12000)) {
		QMessageBox::critical(this, "Lumina Pull", QString("Failed: %1").arg(err));
		return;
	}

	// Map results: statuses length == queries; funcs contains only found entries in order
	size_t fi = 0, found = 0;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i) {
		if (statuses[i] == 0) {
			if (fi >= funcs.size()) break;
			const auto& mf = funcs[fi++];
			lumina::ParsedTLV tlv;
			if (!lumina::parse_function_tlv(mf.data, &tlv)) {
				BinaryNinja::LogWarn("Lumina TLV parse failed for addr 0x%llx", (unsigned long long)addrs[i]);
				continue;
			}
			PullCacheEntry pc;
			pc.have = true;
			pc.tlv = std::move(tlv);
			pc.popularity = mf.popularity;
			pc.len = mf.len;
			pc.remoteName = mf.name;
			pc.raw = mf.data;
			m_pullCache[addrs[i]] = std::move(pc);
			found++;
		}
	}

	QMessageBox::information(this, "Lumina Pull",
		QString("Requested %1 function(s).\nFound %2; updated cache for selected rows.")
			.arg(hashes.size()).arg(found));
}

void FunctionMetadataSidebarWidget::pullAllLumina()
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
		// Apply pull filter to skip PLT stubs and CRT functions
		auto pullFilter = lumina::shouldSkipPull(m_data, func);
		if (pullFilter.shouldSkip) {
			skippedCount++;
			if (debugMode) {
				std::string name = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "<unnamed>";
				BinaryNinja::LogDebug("[Lumina] Pull filter: skipping %s - %s", name.c_str(), pullFilter.reason.c_str());
			}
			continue;
		}

		auto hash = compute_key(m_data, func);
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
		BinaryNinja::LogInfo("[Lumina] Pull filter: skipped %zu PLT/CRT functions", skippedCount);
	}

	if (hashes.empty()) { QMessageBox::information(this, "Lumina Pull All", "No valid function hashes."); return; }

	// Dump debug info if enabled
	if (debugMode) {
		lumina::debug::dumpPullRequest("binja_pull_request.txt", hashes, addrs, names);
		BinaryNinja::LogInfo("[Lumina Debug] Dumped pull request to %s/binja_pull_request.txt",
			lumina::debug::getDebugDir().c_str());
	}

	BinaryNinja::LogInfo("[Lumina] Pull All: querying %zu functions...", hashes.size());

	// Build request
	auto hello = lumina::encode_hello_payload(5);
	auto pull = lumina::encode_pull_payload(1, hashes);  // unk0=1 to match IDA

	// Create client from settings
	std::unique_ptr<lumina::Client> cli(lumina::Client::fromSettings(this));
	QString err;
	std::vector<uint32_t> statuses;
	std::vector<lumina::PulledFunction> pulledFuncs;

	int timeout = lumina::getTimeoutMs();
	if (!cli->helloAndPull(hello, pull, &err, &statuses, &pulledFuncs, timeout)) {
		QMessageBox::critical(this, "Lumina Pull All", QString("Failed: %1").arg(err));
		return;
	}

	// Map results to cache
	size_t fi = 0, found = 0;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i) {
		if (statuses[i] == 0) {
			if (fi >= pulledFuncs.size()) break;
			const auto& mf = pulledFuncs[fi++];
			lumina::ParsedTLV tlv;
			if (!lumina::parse_function_tlv(mf.data, &tlv)) {
				BinaryNinja::LogWarn("[Lumina] TLV parse failed for addr 0x%llx", (unsigned long long)addrs[i]);
				continue;
			}
			PullCacheEntry pc;
			pc.have = true;
			pc.tlv = std::move(tlv);
			pc.popularity = mf.popularity;
			pc.len = mf.len;
			pc.remoteName = mf.name;
			pc.raw = mf.data;
			m_pullCache[addrs[i]] = std::move(pc);
			found++;
		}
	}

	BinaryNinja::LogInfo("[Lumina] Pull All complete: %zu queried, %zu found", hashes.size(), found);
	QMessageBox::information(this, "Lumina Pull All",
		QString("Queried %1 functions.\nFound metadata for %2.\nUse 'Apply' to apply changes.")
			.arg(hashes.size()).arg(found));
}

// Helper to apply Lumina metadata to a single function
// Returns true if any metadata was applied
static bool applyLuminaMetadata(FunctionRef func, const FunctionMetadataSidebarWidget::PullCacheEntry& cache,
                                 size_t& namesApplied, size_t& commentsApplied, size_t& noReturnApplied)
{
	bool applied = false;

	// Apply function name if available and different from current
	if (!cache.remoteName.empty()) {
		std::string currentName = func->GetSymbol() ? func->GetSymbol()->GetShortName() : "";
		// Only rename if current name is auto-generated (sub_*, func_*, etc.) or empty
		bool isAutoName = currentName.empty() ||
		                  currentName.find("sub_") == 0 ||
		                  currentName.find("func_") == 0 ||
		                  currentName.find("j_") == 0;
		if (isAutoName || currentName != cache.remoteName) {
			// Create a new function symbol with the Lumina name
			auto sym = new BinaryNinja::Symbol(
				FunctionSymbol,
				cache.remoteName,
				func->GetStart()
			);
			func->GetView()->DefineUserSymbol(sym);
			namesApplied++;
			applied = true;
			BinaryNinja::LogInfo("[Lumina] Renamed 0x%llx: %s -> %s",
				(unsigned long long)func->GetStart(),
				currentName.c_str(), cache.remoteName.c_str());
		}
	}

	// Apply comment if available
	if (!cache.tlv.comment.empty()) {
		std::string currentComment = func->GetComment();
		if (currentComment != cache.tlv.comment) {
			func->SetComment(cache.tlv.comment);
			commentsApplied++;
			applied = true;
		}
	}

	// Apply no-return attribute if present
	if (cache.tlv.hasNoReturn) {
		bool desiredNoRet = cache.tlv.noReturn;
		bool currentNoRet = !func->CanReturn();
		if (desiredNoRet != currentNoRet) {
			func->SetCanReturn(!desiredNoRet);
			noReturnApplied++;
			applied = true;
		}
	}

	return applied;
}

void FunctionMetadataSidebarWidget::applyPulledToSelected()
{
	if (!m_data) return;
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) {
		QMessageBox::information(this, "Apply Pulled", "No entries selected.");
		return;
	}

	// Function lookup
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	size_t applied = 0, missing = 0;
	size_t namesApplied = 0, commentsApplied = 0, noReturnApplied = 0;

	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = fbyAddr.find(e->address);
		if (fit == fbyAddr.end()) { missing++; continue; }

		if (applyLuminaMetadata(fit->second, cit->second, namesApplied, commentsApplied, noReturnApplied)) {
			applied++;
		}
	}

	// Refresh the table to show updated names
	if (applied > 0) {
		refreshMetadata();
	}

	QString details;
	if (namesApplied > 0) details += QString("%1 renamed, ").arg(namesApplied);
	if (commentsApplied > 0) details += QString("%1 comments, ").arg(commentsApplied);
	if (noReturnApplied > 0) details += QString("%1 no-return, ").arg(noReturnApplied);
	if (details.endsWith(", ")) details.chop(2);

	QMessageBox::information(this, "Apply Pulled",
		QString("Applied metadata to %1 function(s)%2; %3 missing cached data.")
			.arg(applied)
			.arg(details.isEmpty() ? "" : QString(" (%1)").arg(details))
			.arg(missing));
}

void FunctionMetadataSidebarWidget::applyPulledToAll()
{
	if (!m_data) return;

	if (m_pullCache.empty()) {
		QMessageBox::information(this, "Apply All", "No pulled data in cache. Pull functions first.");
		return;
	}

	// Function lookup
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	size_t applied = 0, skipped = 0;
	size_t namesApplied = 0, commentsApplied = 0, noReturnApplied = 0;

	for (const auto& [addr, cache] : m_pullCache) {
		if (!cache.have) { skipped++; continue; }
		auto fit = fbyAddr.find(addr);
		if (fit == fbyAddr.end()) { skipped++; continue; }

		if (applyLuminaMetadata(fit->second, cache, namesApplied, commentsApplied, noReturnApplied)) {
			applied++;
		}
	}

	// Refresh the table to show updated names
	if (applied > 0) {
		refreshMetadata();
	}

	QString details;
	if (namesApplied > 0) details += QString("%1 renamed, ").arg(namesApplied);
	if (commentsApplied > 0) details += QString("%1 comments, ").arg(commentsApplied);
	if (noReturnApplied > 0) details += QString("%1 no-return, ").arg(noReturnApplied);
	if (details.endsWith(", ")) details.chop(2);

	BinaryNinja::LogInfo("[Lumina] Applied metadata to %zu functions (%zu names, %zu comments, %zu no-return)",
		applied, namesApplied, commentsApplied, noReturnApplied);

	QMessageBox::information(this, "Apply All",
		QString("Applied Lumina metadata to %1 function(s)%2.")
			.arg(applied)
			.arg(details.isEmpty() ? "" : QString(" (%1)").arg(details)));
}

void FunctionMetadataSidebarWidget::batchDiffAndApplySelected()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina", "No BinaryView"); return; }
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina", "No entries selected."); return; }

	// Build address->FunctionRef map
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	// Build rows from cache + local
	std::vector<LuminaBulkDiffRow> rows;
	rows.reserve(selected.size());

	size_t missing = 0;
	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = fbyAddr.find(e->address);
		if (fit == fbyAddr.end()) { missing++; continue; }

		FunctionRef func = fit->second;
		LuminaBulkDiffRow row;
		row.address = e->address;
		row.localName = QString::fromStdString(func->GetSymbol() ? func->GetSymbol()->GetFullName() : std::string("<unnamed>"));
		row.remoteName = QString::fromStdString(cit->second.remoteName);
		row.localComment = QString::fromStdString(func->GetComment());
		row.remoteComment = QString::fromStdString(cit->second.tlv.comment);
		row.localNoRet = !func->CanReturn();
		row.remoteNoRet = cit->second.tlv.hasNoReturn ? cit->second.tlv.noReturn : row.localNoRet;

		// default: check only when different
		row.applyComment  = (row.localComment != row.remoteComment);
		row.applyNoReturn = (row.localNoRet  != row.remoteNoRet);
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
		auto fit = fbyAddr.find(r.address);
		if (fit == fbyAddr.end()) continue;
		FunctionRef func = fit->second;

		bool changed = false;
		if (r.applyComment && (r.localComment != r.remoteComment)) {
			func->SetComment(r.remoteComment.toStdString());
			changed = true;
		}
		if (r.applyNoReturn && (r.localNoRet != r.remoteNoRet)) {
			func->SetCanReturn(!r.remoteNoRet);
			changed = true;
		}
		if (changed) applied++;
	}

	QMessageBox::information(this, "Lumina",
		QString("Applied changes to %1 function(s). Missing cache: %2").arg(applied).arg(missing));
}

// FunctionMetadataSidebarWidgetType implementation
FunctionMetadataSidebarWidgetType::FunctionMetadataSidebarWidgetType()
	: SidebarWidgetType(QImage(), "Function Metadata")
{
}

SidebarWidget* FunctionMetadataSidebarWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new FunctionMetadataSidebarWidget(frame, data);
}

// Lumina metadata extraction and logging
void extractAndLogLuminaMetadata(BinaryViewRef data, ViewFrame* frame)
{
	// Print to both stderr (terminal) and Binary Ninja log
	fprintf(stderr, "\n========================================\n");
	fprintf(stderr, "LUMINA METADATA EXTRACTION STARTED\n");
	fprintf(stderr, "========================================\n");

	if (!data)
	{
		fprintf(stderr, "ERROR: No binary view available\n");
		BinaryNinja::LogInfo("No binary view available");
		return;
	}

	auto functions = data->GetAnalysisFunctionList();
	if (functions.empty())
	{
		fprintf(stderr, "ERROR: No functions found in binary\n");
		BinaryNinja::LogInfo("No functions found in binary");
		return;
	}

	// Get the current function if available, otherwise use the first function
	FunctionRef func;
	uint64_t funcStart;
	if (frame)
	{
		View* currentView = frame->getCurrentViewInterface();
		if (currentView && currentView->getCurrentFunction())
		{
			func = currentView->getCurrentFunction();
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===\n");
			fprintf(stderr, "Function Address: 0x%lx\n", funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===");
			BinaryNinja::LogInfo("Function Address: 0x%lx", funcStart);
		}
		else
		{
			// Fallback to first function if no current function
			func = functions[0];
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===\n");
			fprintf(stderr, "Function Address: 0x%lx\n", funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===");
			BinaryNinja::LogInfo("Function Address: 0x%lx", funcStart);
		}
	}
	else
	{
		// Fallback to first function if no frame
		func = functions[0];
		funcStart = func->GetStart();
		fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===\n");
		fprintf(stderr, "Function Address: 0x%lx\n", funcStart);
		BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===");
		BinaryNinja::LogInfo("Function Address: 0x%lx", funcStart);
	}
	
	// 1. FUNCTION IDENTITY
	auto symbol = func->GetSymbol();
	std::string funcName = symbol ? symbol->GetFullName() : "<unnamed>";
	fprintf(stderr, "\n[1] FUNCTION IDENTITY:\n");
	fprintf(stderr, "  Name: %s\n", funcName.c_str());
	fprintf(stderr, "  Start: 0x%lx\n", funcStart);
	uint64_t funcSize = func->GetHighestAddress() - funcStart;
	fprintf(stderr, "  Size: %lu bytes (approx)\n", funcSize);
	
	BinaryNinja::LogInfo("[1] FUNCTION IDENTITY:");
	BinaryNinja::LogInfo("  Name: %s", funcName.c_str());
	BinaryNinja::LogInfo("  Start: 0x%lx", funcStart);
	BinaryNinja::LogInfo("  Size: %lu bytes (approx)", funcSize);
	
	// 2. FUNCTION TYPE INFO (Tag 1)
	fprintf(stderr, "\n[2] FUNCTION TYPE INFO (TLV Tag 1):\n");
	fprintf(stderr, "  No-return flag: %s\n", func->CanReturn() ? "false" : "true");
	BinaryNinja::LogInfo("[2] FUNCTION TYPE INFO (TLV Tag 1):");
	BinaryNinja::LogInfo("  No-return flag: %s", func->CanReturn() ? "false" : "true");
	
	// 3. FUNCTION COMMENTS (Tags 3, 4)
	fprintf(stderr, "\n[3] FUNCTION COMMENTS (TLV Tags 3, 4):\n");
	std::string funcComment = func->GetComment();
	if (!funcComment.empty())
	{
		fprintf(stderr, "  Function comment: %s\n", funcComment.c_str());
		BinaryNinja::LogInfo("  Function comment: %s", funcComment.c_str());
	}
	else
	{
		fprintf(stderr, "  No function comment\n");
		BinaryNinja::LogInfo("  No function comment");
	}
	
	// 4. BASIC BLOCKS INFO
	fprintf(stderr, "\n[4] BASIC BLOCKS:\n");
	auto blocks = func->GetBasicBlocks();
	fprintf(stderr, "  Block count: %zu\n", blocks.size());
	BinaryNinja::LogInfo("[4] BASIC BLOCKS:");
	BinaryNinja::LogInfo("  Block count: %zu", blocks.size());
	
	for (size_t i = 0; i < std::min((size_t)3, blocks.size()); i++)
	{
		auto block = blocks[i];
		uint64_t blockSize = block->GetEnd() - block->GetStart();
		fprintf(stderr, "    Block %zu: 0x%lx - 0x%lx (%lu bytes)\n",
		        i, block->GetStart(), block->GetEnd(), blockSize);
		BinaryNinja::LogInfo("    Block %zu: 0x%lx - 0x%lx (%lu bytes)",
		        i, block->GetStart(), block->GetEnd(), blockSize);
	}
	
	// 5. VARIABLES
	fprintf(stderr, "\n[5] STACK FRAME / VARIABLES (TLV Tag 9):\n");
	auto vars = func->GetVariables();
	fprintf(stderr, "  Variable count: %zu\n", vars.size());
	BinaryNinja::LogInfo("[5] STACK FRAME / VARIABLES (TLV Tag 9):");
	BinaryNinja::LogInfo("  Variable count: %zu", vars.size());
	
	// 6. CROSS REFERENCES
	fprintf(stderr, "\n[6] CROSS REFERENCES:\n");
	auto callSites = func->GetCallSites();
	fprintf(stderr, "  Call sites: %zu locations\n", callSites.size());
	BinaryNinja::LogInfo("[6] CROSS REFERENCES:");
	BinaryNinja::LogInfo("  Call sites: %zu locations", callSites.size());

	// 7. DECOMPILED CODE (HLIL)
	fprintf(stderr, "\n[7] DECOMPILED CODE (HLIL):\n");
	auto hlil = func->GetHighLevelIL();
	if (hlil)
	{
		// Get the root expression index directly using C API
		size_t rootExprIndex = BNGetHighLevelILRootExpr(hlil->GetObject());
		auto lines = hlil->GetExprText(rootExprIndex);
		std::string hlilStr;
		for (const auto& line : lines)
		{
			for (const auto& token : line.tokens)
			{
				hlilStr += token.text;
			}
			hlilStr += "\n";
		}
		fprintf(stderr, "  HLIL Code:\n%s", hlilStr.c_str());
		BinaryNinja::LogInfo("[7] DECOMPILED CODE (HLIL):");
		BinaryNinja::LogInfo("  HLIL Code:\n%s", hlilStr.c_str());
	}
	else
	{
		fprintf(stderr, "  No HLIL available\n");
		BinaryNinja::LogInfo("[7] DECOMPILED CODE (HLIL):");
		BinaryNinja::LogInfo("  No HLIL available");
	}

	// 8. LUMINA CALCREL PATTERN GENERATION
	fprintf(stderr, "\n[8] LUMINA CALCREL PATTERN GENERATION:\n");
	BinaryNinja::LogInfo("[8] LUMINA CALCREL PATTERN GENERATION:");

	// Generate pattern with full details
	lumina::PatternResult pattern = lumina::computePattern(data, func);

	if (pattern.success)
	{
		// Print CalcRel hash
		std::string hashStr;
		for (size_t i = 0; i < pattern.hash.size(); i++)
		{
			char hexByte[4];
			snprintf(hexByte, sizeof(hexByte), "%02x", pattern.hash[i]);
			hashStr += hexByte;
		}
		fprintf(stderr, "  CalcRel Hash: %s\n", hashStr.c_str());
		fprintf(stderr, "  Function Size: %u bytes\n", pattern.func_size);
		fprintf(stderr, "  Normalized Bytes: %zu bytes\n", pattern.normalized.size());
		fprintf(stderr, "  Hash = MD5(normalized || masks) [IDA-compatible]\n");
		BinaryNinja::LogInfo("  CalcRel Hash: %s", hashStr.c_str());
		BinaryNinja::LogInfo("  Function Size: %u bytes", pattern.func_size);
		BinaryNinja::LogInfo("  Normalized Bytes: %zu bytes", pattern.normalized.size());
		BinaryNinja::LogInfo("  Hash = MD5(normalized || masks) [IDA-compatible]");

		// Show first 64 bytes of normalized data
		fprintf(stderr, "\n  Normalized bytes (first 64):\n");
		BinaryNinja::LogInfo("  Normalized bytes (first 64):");
		const size_t bytesPerLine = 16;
		const size_t maxShow = std::min(pattern.normalized.size(), (size_t)64);
		for (size_t i = 0; i < maxShow; i += bytesPerLine)
		{
			char line[256];
			int pos = snprintf(line, sizeof(line), "    %04zx: ", i);
			size_t lineEnd = std::min(i + bytesPerLine, maxShow);
			for (size_t j = i; j < lineEnd; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", pattern.normalized[j]);
			}
			fprintf(stderr, "%s\n", line);
			BinaryNinja::LogInfo("%s", line);
		}

		// Show mask bytes for same range
		fprintf(stderr, "\n  Mask bytes (first 64, 0xFF=masked, 0x00=kept):\n");
		BinaryNinja::LogInfo("  Mask bytes (first 64, 0xFF=masked, 0x00=kept):");
		for (size_t i = 0; i < maxShow && i < pattern.masks.size(); i += bytesPerLine)
		{
			char line[256];
			int pos = snprintf(line, sizeof(line), "    %04zx: ", i);
			size_t lineEnd = std::min(i + bytesPerLine, std::min(maxShow, pattern.masks.size()));
			for (size_t j = i; j < lineEnd; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", pattern.masks[j]);
			}
			fprintf(stderr, "%s\n", line);
			BinaryNinja::LogInfo("%s", line);
		}
	}
	else
	{
		fprintf(stderr, "  Pattern generation failed: %s\n", pattern.error.c_str());
		BinaryNinja::LogInfo("  Pattern generation failed: %s", pattern.error.c_str());
	}

	// 9. ENCODED TLV PAYLOAD
	fprintf(stderr, "\n[9] ENCODED TLV PAYLOAD:\n");
	BinaryNinja::LogInfo("[9] ENCODED TLV PAYLOAD:");

	auto encodedFunc = encodeOneFunction(data, func);
	const auto& payload = encodedFunc.func_data;

	if (!payload.empty())
	{
		fprintf(stderr, "  Payload size: %zu bytes\n", payload.size());
		fprintf(stderr, "  Hexdump:\n");
		BinaryNinja::LogInfo("  Payload size: %zu bytes", payload.size());
		BinaryNinja::LogInfo("  Hexdump:");

		// Print hexdump in standard format: offset | hex bytes | ASCII
		const size_t bytesPerLine = 16;
		for (size_t i = 0; i < payload.size(); i += bytesPerLine)
		{
			// Print offset
			char line[256];
			int pos = snprintf(line, sizeof(line), "    %08zx  ", i);

			// Print hex bytes
			size_t lineEnd = std::min(i + bytesPerLine, payload.size());
			for (size_t j = i; j < lineEnd; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", payload[j]);
				if ((j - i) == 7) // Extra space in the middle
				{
					pos += snprintf(line + pos, sizeof(line) - pos, " ");
				}
			}

			// Pad if incomplete line
			for (size_t j = lineEnd; j < i + bytesPerLine; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "   ");
				if ((j - i) == 7)
				{
					pos += snprintf(line + pos, sizeof(line) - pos, " ");
				}
			}

			// Print ASCII representation
			pos += snprintf(line + pos, sizeof(line) - pos, " |");
			for (size_t j = i; j < lineEnd; j++)
			{
				unsigned char c = payload[j];
				pos += snprintf(line + pos, sizeof(line) - pos, "%c", (c >= 32 && c <= 126) ? c : '.');
			}
			pos += snprintf(line + pos, sizeof(line) - pos, "|");

			fprintf(stderr, "%s\n", line);
			BinaryNinja::LogInfo("%s", line);
		}
	}
	else
	{
		fprintf(stderr, "  No payload data\n");
		BinaryNinja::LogInfo("  No payload data");
	}

	fprintf(stderr, "\n=== END LUMINA METADATA EXTRACTION ===\n");
	fprintf(stderr, "Plugin successfully extracted basic Lumina-relevant metadata\n");
	fprintf(stderr, "========================================\n\n");
	fflush(stderr);

	BinaryNinja::LogInfo("=== END LUMINA METADATA EXTRACTION ===");
	BinaryNinja::LogInfo("Plugin successfully extracted basic Lumina-relevant metadata");
}

// Helper to compute CalcRel hash for a function and return as hex string
static std::string computeHashString(BinaryViewRef bvRef, FunctionRef func)
{
	lumina::PatternResult pattern = lumina::computePattern(bvRef, func);
	if (!pattern.success)
		return "";

	char hashStr[33];
	for (int i = 0; i < 16; i++)
		snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
	return std::string(hashStr);
}

// Auto-query Lumina server for function metadata
static void autoQueryLumina(BinaryView* view)
{
	BinaryNinja::LogInfo("[Lumina] Auto-querying Lumina server for function metadata...");

	BinaryViewRef bvRef = view;
	auto functions = view->GetAnalysisFunctionList();
	if (functions.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No functions to query");
		return;
	}

	// Build hash list
	std::vector<std::array<uint8_t, 16>> hashes;
	std::vector<uint64_t> addrs;
	std::vector<FunctionRef> funcRefs;

	for (auto& func : functions)
	{
		lumina::PatternResult pattern = lumina::computePattern(bvRef, func);
		if (pattern.success)
		{
			hashes.push_back(pattern.hash);
			addrs.push_back(func->GetStart());
			funcRefs.push_back(func);
		}
	}

	if (hashes.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No valid function hashes to query");
		return;
	}

	BinaryNinja::LogInfo("[Lumina] Querying %zu functions from server %s:%d (TLS: %s)",
		hashes.size(),
		lumina::getHost().c_str(),
		lumina::getPort(),
		lumina::useTls() ? "yes" : "no");

	// Build request
	auto hello = lumina::encode_hello_payload(5);
	auto pull = lumina::encode_pull_payload(1, hashes);  // unk0=1 to match IDA

	// Create client from settings
	std::unique_ptr<lumina::Client> cli(lumina::Client::fromSettings(nullptr));
	QString err;
	std::vector<uint32_t> statuses;
	std::vector<lumina::PulledFunction> pulledFuncs;

	int timeout = lumina::getTimeoutMs();
	if (!cli->helloAndPull(hello, pull, &err, &statuses, &pulledFuncs, timeout))
	{
		BinaryNinja::LogError("[Lumina] Auto-query failed: %s", err.toStdString().c_str());
		return;
	}

	// Apply results
	size_t fi = 0, applied = 0;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i)
	{
		if (statuses[i] == 0 && fi < pulledFuncs.size())
		{
			const auto& pf = pulledFuncs[fi++];
			FunctionRef func = funcRefs[i];

			// Parse TLV and apply metadata
			lumina::ParsedTLV tlv;
			if (lumina::parse_function_tlv(pf.data, &tlv))
			{
				bool changed = false;

				// Apply function name if we have one and current is unnamed
				if (!pf.name.empty())
				{
					auto sym = func->GetSymbol();
					std::string currentName = sym ? sym->GetFullName() : "";
					if (currentName.empty() || currentName.find("sub_") == 0)
					{
						// Create a new symbol with the Lumina name
						BinaryNinja::Symbol* newSym = new BinaryNinja::Symbol(
							BNSymbolType::FunctionSymbol,
							pf.name,
							func->GetStart());
						view->DefineUserSymbol(newSym);
						changed = true;
						BinaryNinja::LogInfo("[Lumina] Renamed 0x%llx to %s",
							(unsigned long long)func->GetStart(), pf.name.c_str());
					}
				}

				// Apply comment
				if (!tlv.comment.empty() && func->GetComment().empty())
				{
					func->SetComment(tlv.comment);
					changed = true;
				}

				if (changed)
					applied++;
			}
		}
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Auto-query complete: %zu queried, %zu found, %zu applied",
		hashes.size(), pulledFuncs.size(), applied);
	BinaryNinja::LogInfo("[Lumina] ========================================");
}

// Global callback for when initial analysis completes on any binary view
static void onInitialAnalysisComplete(BinaryView* view)
{
	if (!view)
		return;

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo("[Lumina] Initial analysis complete - computing CalcRel for all functions");
	BinaryNinja::LogInfo("[Lumina] ========================================");

	auto functions = view->GetAnalysisFunctionList();
	if (functions.empty())
	{
		BinaryNinja::LogInfo("[Lumina] No functions found in binary");
		return;
	}

	BinaryNinja::LogInfo("[Lumina] Computing CalcRel for %zu functions...", functions.size());

	// Create a BinaryViewRef from the raw pointer
	BinaryViewRef bvRef = view;

	size_t success = 0;
	size_t failed = 0;

	for (auto& func : functions)
	{
		std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
		uint64_t funcStart = func->GetStart();

		lumina::PatternResult pattern = lumina::computePattern(bvRef, func);

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

	// Auto-query Lumina if enabled in settings
	if (lumina::autoQueryOnAnalysis())
	{
		autoQueryLumina(view);
	}
}

// Plugin initialization
extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		// Register Lumina settings
		lumina::registerSettings();

		// Register the sidebar widget type
		Sidebar::addSidebarWidgetType(new FunctionMetadataSidebarWidgetType());

		// Register global callback for when initial analysis completes on any binary
		BinaryViewType::RegisterBinaryViewInitialAnalysisCompletionEvent(onInitialAnalysisComplete);

		LogInfo("[Lumina] Function Metadata Sidebar plugin loaded");
		LogInfo("[Lumina] Server: %s:%d (TLS: %s, Verify: %s)",
			lumina::getHost().c_str(),
			lumina::getPort(),
			lumina::useTls() ? "yes" : "no",
			lumina::verifyTls() ? "yes" : "no");
		LogInfo("[Lumina] Auto-query: %s", lumina::autoQueryOnAnalysis() ? "enabled" : "disabled");

		return true;
	}
}

