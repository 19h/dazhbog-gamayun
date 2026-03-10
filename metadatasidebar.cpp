#include "metadatasidebar.h"
#include "lumina_codec.h"
#include "lumina_metadata.h"
#include "lumina_type_decoder.h"
#include "pattern_gen.h"
#include "lumina_settings.h"
#include "debug_dump.h"
// Forward declaration for View class
class View;
#include <QDialog>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QHeaderView>
#include <QPlainTextEdit>
#include <QProcessEnvironment>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>

// Forward declaration
void extractAndLogLuminaMetadata(BinaryViewRef data, ViewFrame* frame = nullptr);

static std::unique_ptr<lumina::Client> createLuminaClient(QObject* parent)
{
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	QString host = QString::fromStdString(lumina::getHost());
	if (env.contains("BN_LUMINA_HOST"))
		host = env.value("BN_LUMINA_HOST");

	quint16 port = lumina::getPort();
	if (env.contains("BN_LUMINA_PORT"))
	{
		bool ok = false;
		const quint16 envPort = env.value("BN_LUMINA_PORT").toUShort(&ok);
		if (ok)
			port = envPort;
	}

	return std::make_unique<lumina::Client>(
		host,
		port,
		parent,
		lumina::useTls(),
		lumina::verifyTls());
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

static lumina::FunctionMetadata parsePulledMetadata(const std::vector<uint8_t>& raw, uint64_t address)
{
	lumina::FunctionMetadata metadata = lumina::parseFunctionMetadata(raw);
	if (!metadata.ok())
	{
		for (const auto& error : metadata.errors)
		{
			BinaryNinja::LogWarn("[Lumina] Metadata parse issue for 0x%llx: %s",
				(unsigned long long)address,
				error.c_str());
		}
	}
	return metadata;
}

static std::string formatPulledMetadataReport(
	uint64_t address,
	const FunctionMetadataSidebarWidget::PullCacheEntry& cache)
{
	std::ostringstream out;
	out << "Address: 0x" << std::hex << std::uppercase << address << std::dec << "\n";
	out << "Remote Name: " << (cache.remoteName.empty() ? "<unnamed>" : cache.remoteName) << "\n";
	out << "Popularity: " << cache.popularity << "\n";
	out << "Remote Length: " << cache.len << "\n";
	out << "Raw Metadata Size: " << cache.raw.size() << " bytes\n\n";
	out << lumina::formatFunctionMetadata(cache.metadata, true);
	return out.str();
}

static void showMetadataInspector(QWidget* parent, const QString& title, const QString& text)
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

struct LuminaApplyStats
{
	size_t namesApplied = 0;
	size_t functionCommentsApplied = 0;
	size_t functionTypesApplied = 0;
	size_t addressCommentsApplied = 0;
	size_t stackVariablesApplied = 0;
	size_t tagsApplied = 0;
};

static int64_t reinterpretSignedUint64(uint64_t value)
{
	int64_t signedValue = 0;
	static_assert(sizeof(signedValue) == sizeof(value), "unexpected integer width mismatch");
	std::memcpy(&signedValue, &value, sizeof(signedValue));
	return signedValue;
}

static BinaryNinja::Ref<BinaryNinja::TagType> getOrCreateLuminaTagType(
	BinaryViewRef view,
	const std::string& name,
	const std::string& icon = "L")
{
	if (!view)
		return nullptr;

	auto tagType = view->GetTagTypeByName(name, UserTagType);
	if (tagType)
		return tagType;

	tagType = new BinaryNinja::TagType(view.GetPtr(), name, icon, true, UserTagType);
	view->AddTagType(tagType);
	return tagType;
}

static bool addLuminaFunctionTag(
	FunctionRef func,
	const std::string& tagTypeName,
	const std::string& data,
	LuminaApplyStats& stats)
{
	if (!func || data.empty())
		return false;

	auto tagType = getOrCreateLuminaTagType(func->GetView(), tagTypeName);
	if (!tagType)
		return false;

	auto tag = func->CreateUserFunctionTag(tagType, data, true);
	if (!tag)
		return false;

	stats.tagsApplied++;
	return true;
}

static bool addLuminaAddressTag(
	FunctionRef func,
	uint64_t addr,
	const std::string& tagTypeName,
	const std::string& data,
	LuminaApplyStats& stats)
{
	if (!func || data.empty())
		return false;

	auto arch = func->GetArchitecture();
	if (!arch)
		return false;

	auto tagType = getOrCreateLuminaTagType(func->GetView(), tagTypeName);
	if (!tagType)
		return false;

	auto tag = func->CreateUserAddressTag(arch.GetPtr(), addr, tagType, data, true);
	if (!tag)
		return false;

	stats.tagsApplied++;
	return true;
}

static std::optional<uint64_t> resolveLuminaChunkAddress(
	FunctionRef func,
	uint32_t functionChunkNumber,
	uint32_t functionChunkOffset)
{
	if (!func)
		return std::nullopt;

	auto ranges = func->GetAddressRanges();
	if (ranges.empty())
		return std::nullopt;

	std::sort(ranges.begin(), ranges.end(), [](const BNAddressRange& left, const BNAddressRange& right) {
		if (left.start != right.start)
			return left.start < right.start;
		return left.end < right.end;
	});

	const uint64_t funcStart = func->GetStart();
	auto entryIt = std::find_if(ranges.begin(), ranges.end(), [&](const BNAddressRange& range) {
		return funcStart >= range.start && funcStart < range.end;
	});
	if (entryIt != ranges.end() && entryIt != ranges.begin())
		std::rotate(ranges.begin(), entryIt, entryIt + 1);

	if (functionChunkNumber >= ranges.size())
		return std::nullopt;

	const BNAddressRange& range = ranges[functionChunkNumber];
	const uint64_t rangeSize = range.end > range.start ? (range.end - range.start) : 0;
	if (functionChunkOffset >= rangeSize)
		return std::nullopt;

	uint64_t addr = range.start + functionChunkOffset;
	auto arch = func->GetArchitecture();
	uint64_t instructionStart = addr;
	if (arch && func->GetInstructionContainingAddress(arch.GetPtr(), addr, &instructionStart))
		addr = instructionStart;
	return addr;
}

static std::string buildMergedFunctionComment(const lumina::FunctionMetadata& metadata)
{
	const std::string primary = metadata.functionComment.value_or(std::string());
	const std::string repeatable = metadata.repeatableFunctionComment.value_or(std::string());
	if (primary.empty())
		return repeatable;
	if (repeatable.empty() || repeatable == primary)
		return primary;

	return primary + "\n\n[Lumina Repeatable Comment]\n" + repeatable;
}

static std::string buildMergedAddressComment(
	const std::vector<std::string>& normalComments,
	const std::vector<std::string>& repeatableComments,
	const std::vector<std::string>& previousExtraComments,
	const std::vector<std::string>& nextExtraComments)
{
	if (repeatableComments.empty() && previousExtraComments.empty() && nextExtraComments.empty()
		&& normalComments.size() == 1)
	{
		return normalComments.front();
	}

	std::ostringstream out;
	auto appendSection = [&](const char* label, const std::vector<std::string>& lines) {
		if (lines.empty())
			return;
		if (out.tellp() > 0)
			out << "\n\n";
		out << '[' << label << "]\n";
		for (size_t i = 0; i < lines.size(); ++i)
		{
			if (i != 0)
				out << "\n";
			out << lines[i];
		}
	};

	appendSection("Lumina Comment", normalComments);
	appendSection("Lumina Repeatable Comment", repeatableComments);
	appendSection("Lumina Extra Previous", previousExtraComments);
	appendSection("Lumina Extra Next", nextExtraComments);
	return out.str();
}

static bool parseNamedTypeDeclaration(
	BinaryViewRef view,
	const std::string& declaration,
	BinaryNinja::Ref<BinaryNinja::Type>* outType,
	std::string* error)
{
	if (!view || outType == nullptr)
		return false;

	BinaryNinja::QualifiedNameAndType parsed;
	std::string parseErrors;
	if (!view->ParseTypeString(declaration, parsed, parseErrors))
	{
		if (error != nullptr)
			*error = parseErrors.empty() ? "Binary Ninja type parser rejected declaration" : parseErrors;
		return false;
	}

	*outType = parsed.type;
	return true;
}

static bool parseFunctionTypeFromMetadata(
	FunctionRef func,
	const lumina::MdTypeParts& typeParts,
	BinaryNinja::Ref<BinaryNinja::Type>* outType,
	std::string* error)
{
	const auto rendered = lumina::decodeTinfoDeclWithName(
		typeParts.typeBytes,
		typeParts.fieldsBytes,
		"__lumina_function");
	if (!rendered.ok())
	{
		if (error != nullptr)
			*error = rendered.error;
		return false;
	}
	return parseNamedTypeDeclaration(func->GetView(), rendered.declaration, outType, error);
}

static bool parseStackTypeFromMetadata(
	FunctionRef func,
	const lumina::SerializedTinfo& typeInfo,
	BinaryNinja::Ref<BinaryNinja::Type>* outType,
	std::string* error)
{
	const auto rendered = lumina::decodeTinfoDeclWithName(
		typeInfo.typeBytes,
		typeInfo.fieldsBytes,
		"__lumina_var");
	if (!rendered.ok())
	{
		if (error != nullptr)
			*error = rendered.error;
		return false;
	}
	return parseNamedTypeDeclaration(func->GetView(), rendered.declaration, outType, error);
}

static std::vector<int64_t> candidateFrameOffsets(
	const lumina::FrameDescription& frame,
	const lumina::FrameMember& member,
	size_t addressSize)
{
	std::vector<int64_t> offsets;
	if (!member.offset)
		return offsets;

	auto addOffset = [&](int64_t value) {
		if (std::find(offsets.begin(), offsets.end(), value) == offsets.end())
			offsets.push_back(value);
	};

	const uint64_t rawOffset = *member.offset;
	const int64_t signedOffset = reinterpretSignedUint64(rawOffset);
	const int64_t frameSize = static_cast<int64_t>(frame.frameSize);
	const int64_t savedRegisters = static_cast<int64_t>(frame.savedRegistersSize);
	const int64_t pointerSize = static_cast<int64_t>(addressSize == 0 ? 8 : addressSize);
	const int64_t argumentSize = static_cast<int64_t>(frame.argumentSize);

	addOffset(signedOffset);
	if (rawOffset <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
		addOffset(static_cast<int64_t>(rawOffset));

	for (int64_t base : {frameSize, frameSize + savedRegisters, frameSize + savedRegisters + pointerSize,
		frameSize + savedRegisters + pointerSize + argumentSize})
	{
		addOffset(signedOffset - base);
		if (rawOffset <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
			addOffset(static_cast<int64_t>(rawOffset) - base);
	}

	return offsets;
}

static std::optional<int64_t> findBestStackOffset(
	FunctionRef func,
	const lumina::FrameDescription& frame,
	const lumina::FrameMember& member)
{
	if (!func)
		return std::nullopt;

	const auto layout = func->GetStackLayout();
	auto arch = func->GetArchitecture();
	const size_t addressSize = arch ? arch->GetAddressSize() : 8;
	const auto offsets = candidateFrameOffsets(frame, member, addressSize);

	std::optional<int64_t> bestOffset;
	int bestScore = std::numeric_limits<int>::min();
	for (int64_t candidate : offsets)
	{
		int score = 0;
		auto it = layout.find(candidate);
		if (it != layout.end())
			score += 100;

		if (member.offset)
		{
			if (*member.offset < frame.frameSize && candidate < 0)
				score += 10;
			if (*member.offset >= frame.frameSize && candidate >= 0)
				score += 10;
		}

		if (member.nbytes && it != layout.end())
		{
			for (const auto& existing : it->second)
			{
				auto existingType = existing.type.GetValue();
				if (existingType && existingType->GetWidth() == *member.nbytes)
				{
					score += 20;
					break;
				}
			}
		}

		if (score > bestScore)
		{
			bestScore = score;
			bestOffset = candidate;
		}
	}

	if (bestScore < 100)
		return std::nullopt;
	return bestOffset;
}

static std::string formatFrameMemberTagData(const lumina::FrameMember& member)
{
	std::ostringstream out;
	if (member.offset)
		out << "offset=" << *member.offset << "\n";
	if (member.name)
		out << "name=" << *member.name << "\n";
	if (member.nbytes)
		out << "nbytes=" << *member.nbytes << "\n";
	if (member.tinfo)
	{
		if (member.tinfo->declaration)
			out << "type=" << *member.tinfo->declaration << "\n";
		if (member.tinfo->decodeError)
			out << "type_decode_error=" << *member.tinfo->decodeError << "\n";
	}
	if (member.comment)
		out << "comment=" << *member.comment << "\n";
	if (member.repeatableComment)
		out << "repeatable_comment=" << *member.repeatableComment << "\n";
	if (member.infoRepresentation)
		out << "operand_repr_flags=0x" << std::hex << std::uppercase << member.infoRepresentation->flags << std::dec << "\n";
	return out.str();
}

static std::string formatOperandRepresentationTagData(const lumina::InstructionOperandRepresentation& entry)
{
	std::ostringstream out;
	out << "chunk=" << entry.functionChunkNumber << " off=0x" << std::hex << std::uppercase
		<< entry.functionChunkOffset << std::dec << '\n';
	out << "flags=0x" << std::hex << std::uppercase << entry.representation.flags << std::dec;
	for (const auto& operand : entry.representation.operands)
	{
		out << "\noperand[" << operand.operandIndex << "]=" << operand.typeName;
		if (operand.offsetReference)
		{
			out << " target=0x" << std::hex << std::uppercase << operand.offsetReference->target
				<< " base=0x" << operand.offsetReference->base
				<< std::dec << " tdelta=" << operand.offsetReference->targetDelta
				<< " ri_flags=0x" << std::hex << std::uppercase << operand.offsetReference->flags << std::dec;
		}
	}
	return out.str();
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
	}
	
	menu.addAction("Refresh", [this]() { m_model->refresh(); });
	menu.addAction("Select All", [this]() { m_model->selectAll(); });
	menu.addAction("Select None", [this]() { m_model->selectNone(); });
	
	// Lumina operations
	menu.addSeparator();
	menu.addAction("Pull Selected (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pullSelectedLumina();
	});
	menu.addAction("Pull All (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pullAllLumina();
	});
	menu.addAction("Inspect Pulled Metadata", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->inspectPulledSelected();
	});
	menu.addAction("Log Pulled Metadata", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->logPulledSelected();
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
	connect(m_refreshButton, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::refreshMetadata);
	connect(m_pullSelected, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pullSelectedLumina);
	connect(m_inspectPulled, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::inspectPulledSelected);
	connect(m_applyPulled, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::applyPulledToSelected);
	connect(m_pullAll, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pullAllLumina);
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
	size_t skippedCount = 0;
	hashes.reserve(selected.size());
	addrs.reserve(selected.size());
	for (auto* e : selected) {
		auto it = fbyAddr.find(e->address);
		if (it == fbyAddr.end()) continue;
		auto pullFilter = lumina::shouldSkipPull(m_data, it->second);
		if (pullFilter.shouldSkip) {
			skippedCount++;
			BinaryNinja::LogDebug("[Lumina] Pull filter: skipping %s - %s",
				it->second->GetSymbol() ? it->second->GetSymbol()->GetShortName().c_str() : "<unnamed>",
				pullFilter.reason.c_str());
			continue;
		}
		hashes.push_back(compute_key(m_data, it->second));
		addrs.push_back(e->address);
	}
	if (hashes.empty()) { QMessageBox::information(this, "Lumina Pull", "No functions resolved."); return; }

	const auto hello = lumina::build_hello_request();
	const auto pull = lumina::build_pull_request(0, hashes);

	auto cli = createLuminaClient(this);
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
			const auto& mf = funcs[fi++];
			PullCacheEntry pc;
			pc.have = true;
			pc.metadata = parsePulledMetadata(mf.data, addrs[i]);
			pc.popularity = mf.popularity;
			pc.len = mf.len;
			pc.remoteName = mf.name;
			pc.raw = mf.data;
			m_pullCache[addrs[i]] = std::move(pc);
			found++;
		}
	}

	QMessageBox::information(this, "Lumina Pull",
		QString("Requested %1 function(s).\nFound %2; updated cache for selected rows.%3")
			.arg(hashes.size())
			.arg(found)
			.arg(skippedCount > 0 ? QString("\nSkipped %1 function(s) due to the reliability filter.").arg(skippedCount) : QString()));
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

	auto cli = createLuminaClient(this);
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
			const auto& mf = pulledFuncs[fi++];
			PullCacheEntry pc;
			pc.have = true;
			pc.metadata = parsePulledMetadata(mf.data, addrs[i]);
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

void FunctionMetadataSidebarWidget::inspectPulledSelected()
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
		report << formatPulledMetadataReport(entry->address, it->second);
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

void FunctionMetadataSidebarWidget::logPulledSelected()
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
		report << formatPulledMetadataReport(entry->address, it->second);
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

// Helper to apply Lumina metadata to a single function
// Returns true if any metadata was applied
static bool applyLuminaMetadata(
	FunctionRef func,
	const FunctionMetadataSidebarWidget::PullCacheEntry& cache,
	LuminaApplyStats& stats)
{
	bool applied = false;
	auto view = func->GetView();

	if (!func || !view)
		return false;

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
			view->DefineUserSymbol(sym);
			stats.namesApplied++;
			applied = true;
			BinaryNinja::LogInfo("[Lumina] Renamed 0x%llx: %s -> %s",
				(unsigned long long)func->GetStart(),
				currentName.c_str(), cache.remoteName.c_str());
		}
	}

	const std::string remoteComment = buildMergedFunctionComment(cache.metadata);
	if (!remoteComment.empty()) {
		std::string currentComment = func->GetComment();
		if (currentComment != remoteComment) {
			func->SetComment(remoteComment);
			stats.functionCommentsApplied++;
			applied = true;
		}
	}

	if (cache.metadata.typeParts)
	{
		BinaryNinja::Ref<BinaryNinja::Type> parsedType;
		std::string typeError;
		if (parseFunctionTypeFromMetadata(func, *cache.metadata.typeParts, &parsedType, &typeError) && parsedType)
		{
			auto currentType = func->GetType();
			const std::string currentTypeString = currentType ? currentType->GetString() : std::string();
			const std::string parsedTypeString = parsedType->GetString();
			if (currentTypeString != parsedTypeString)
			{
				func->SetUserType(parsedType.GetPtr());
				stats.functionTypesApplied++;
				applied = true;
			}
		}
		else if (!typeError.empty())
		{
			std::string tagData = typeError;
			if (cache.metadata.typeParts->declaration)
				tagData += "\n\nDeclaration:\n" + *cache.metadata.typeParts->declaration;
			if (addLuminaFunctionTag(func, "Lumina Type", tagData, stats))
				applied = true;
		}
	}

	if (cache.metadata.vdElapsed)
	{
		std::string tagData = "vd_elapsed=" + std::to_string(*cache.metadata.vdElapsed);
		if (addLuminaFunctionTag(func, "Lumina Info", tagData, stats))
			applied = true;
	}

	if (cache.metadata.frameDescription)
	{
		const auto layout = func->GetStackLayout();
		for (const auto& member : cache.metadata.frameDescription->members)
		{
			bool memberApplied = false;
			auto stackOffset = findBestStackOffset(func, *cache.metadata.frameDescription, member);
			if (stackOffset)
			{
				auto existingIt = layout.find(*stackOffset);
				std::string variableName = member.name.value_or(std::string());
				BinaryNinja::Ref<BinaryNinja::Type> variableType;
				std::string typeError;
				if (member.tinfo)
					parseStackTypeFromMetadata(func, *member.tinfo, &variableType, &typeError);

				if (existingIt != layout.end() && !existingIt->second.empty())
				{
					const auto& existing = existingIt->second.front();
					if (variableName.empty())
						variableName = existing.name;
					if (!variableType && existing.type.GetValue())
						variableType = existing.type.GetValue();
				}

				if (!variableType && member.nbytes)
					variableType = BinaryNinja::Type::IntegerType(*member.nbytes, false);

				if (variableType && !variableName.empty())
				{
					func->CreateUserStackVariable(
						*stackOffset,
						BinaryNinja::Confidence<BinaryNinja::Ref<BinaryNinja::Type>>(variableType),
						variableName);
					stats.stackVariablesApplied++;
					applied = true;
					memberApplied = true;
				}
				else if (!typeError.empty())
				{
					std::string tagData = "stack_offset=" + std::to_string(*stackOffset) + "\n" + typeError;
					if (addLuminaFunctionTag(func, "Lumina Frame", tagData, stats))
						applied = true;
				}
			}

			if (!memberApplied && (member.comment || member.repeatableComment || member.infoRepresentation || member.tinfo))
			{
				if (addLuminaFunctionTag(func, "Lumina Frame", formatFrameMemberTagData(member), stats))
					applied = true;
			}
		}
	}

	struct AddressMetadataBundle
	{
		std::vector<std::string> normalComments;
		std::vector<std::string> repeatableComments;
		std::vector<std::string> previousExtraComments;
		std::vector<std::string> nextExtraComments;
	};
	std::map<uint64_t, AddressMetadataBundle> bundles;

	for (const auto& comment : cache.metadata.instructionComments)
	{
		auto addr = resolveLuminaChunkAddress(func, comment.functionChunkNumber, comment.functionChunkOffset);
		if (!addr)
		{
			if (addLuminaFunctionTag(func, "Lumina Comment", comment.comment, stats))
				applied = true;
			continue;
		}
		bundles[*addr].normalComments.push_back(comment.comment);
	}

	for (const auto& comment : cache.metadata.repeatableInstructionComments)
	{
		auto addr = resolveLuminaChunkAddress(func, comment.functionChunkNumber, comment.functionChunkOffset);
		if (!addr)
		{
			if (addLuminaFunctionTag(func, "Lumina Comment", comment.comment, stats))
				applied = true;
			continue;
		}
		bundles[*addr].repeatableComments.push_back(comment.comment);
	}

	for (const auto& comment : cache.metadata.extraCommentEntries)
	{
		auto addr = resolveLuminaChunkAddress(func, comment.functionChunkNumber, comment.functionChunkOffset);
		if (!addr)
		{
			if (addLuminaFunctionTag(func, "Lumina Comment", comment.previous + "\n" + comment.next, stats))
				applied = true;
			continue;
		}
		if (!comment.previous.empty())
			bundles[*addr].previousExtraComments.push_back(comment.previous);
		if (!comment.next.empty())
			bundles[*addr].nextExtraComments.push_back(comment.next);
	}

	for (const auto& [addr, bundle] : bundles)
	{
		const std::string mergedComment = buildMergedAddressComment(
			bundle.normalComments,
			bundle.repeatableComments,
			bundle.previousExtraComments,
			bundle.nextExtraComments);
		if (mergedComment.empty())
			continue;

		if (func->GetCommentForAddress(addr) != mergedComment)
		{
			func->SetCommentForAddress(addr, mergedComment);
			stats.addressCommentsApplied++;
			applied = true;
		}
	}

	for (const auto& point : cache.metadata.userStackPointEntries)
	{
		std::ostringstream data;
		data << "chunk=" << point.functionChunkNumber
			<< " off=0x" << std::hex << std::uppercase << point.functionChunkOffset << std::dec
			<< " delta=" << point.delta;

		auto addr = resolveLuminaChunkAddress(func, point.functionChunkNumber, point.functionChunkOffset);
		if (addr)
		{
			if (addLuminaAddressTag(func, *addr, "Lumina Stack Point", data.str(), stats))
				applied = true;
		}
		else if (addLuminaFunctionTag(func, "Lumina Stack Point", data.str(), stats))
		{
			applied = true;
		}
	}
	if (cache.metadata.userStackPointEntries.empty() && cache.metadata.userStackPoints
		&& !cache.metadata.userStackPoints->printableTexts.empty())
	{
		std::ostringstream tagData;
		for (size_t i = 0; i < cache.metadata.userStackPoints->printableTexts.size(); ++i)
		{
			if (i != 0)
				tagData << '\n';
			tagData << cache.metadata.userStackPoints->printableTexts[i];
		}
		if (addLuminaFunctionTag(func, "Lumina Stack Point", tagData.str(), stats))
			applied = true;
	}

	for (const auto& entry : cache.metadata.instructionOperandRepresentations)
	{
		auto addr = resolveLuminaChunkAddress(func, entry.functionChunkNumber, entry.functionChunkOffset);
		const std::string tagData = formatOperandRepresentationTagData(entry);
		if (addr)
		{
			if (addLuminaAddressTag(func, *addr, "Lumina Operand", tagData, stats))
				applied = true;
		}
		else if (addLuminaFunctionTag(func, "Lumina Operand", tagData, stats))
		{
			applied = true;
		}
	}
	if (cache.metadata.instructionOperandRepresentations.empty())
	{
		if (cache.metadata.operandRepresentations && !cache.metadata.operandRepresentations->printableTexts.empty())
		{
			std::ostringstream tagData;
			for (size_t i = 0; i < cache.metadata.operandRepresentations->printableTexts.size(); ++i)
			{
				if (i != 0)
					tagData << '\n';
				tagData << cache.metadata.operandRepresentations->printableTexts[i];
			}
			if (addLuminaFunctionTag(func, "Lumina Operand", tagData.str(), stats))
				applied = true;
		}
		if (cache.metadata.operandRepresentationsEx && !cache.metadata.operandRepresentationsEx->printableTexts.empty())
		{
			std::ostringstream tagData;
			for (size_t i = 0; i < cache.metadata.operandRepresentationsEx->printableTexts.size(); ++i)
			{
				if (i != 0)
					tagData << '\n';
				tagData << cache.metadata.operandRepresentationsEx->printableTexts[i];
			}
			if (addLuminaFunctionTag(func, "Lumina Operand", tagData.str(), stats))
				applied = true;
		}
	}
	if (cache.metadata.extraCommentEntries.empty() && !cache.metadata.extraComments.empty())
	{
		std::ostringstream tagData;
		for (size_t i = 0; i < cache.metadata.extraComments.size(); ++i)
		{
			if (i != 0)
				tagData << '\n';
			tagData << cache.metadata.extraComments[i];
		}
		if (addLuminaFunctionTag(func, "Lumina Comment", tagData.str(), stats))
			applied = true;
	}

	if (!cache.metadata.errors.empty())
	{
		std::ostringstream errorData;
		for (size_t i = 0; i < cache.metadata.errors.size(); ++i)
		{
			if (i != 0)
				errorData << '\n';
			errorData << cache.metadata.errors[i];
		}
		if (addLuminaFunctionTag(func, "Lumina Parse Issues", errorData.str(), stats))
			applied = true;
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
	LuminaApplyStats stats;

	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = fbyAddr.find(e->address);
		if (fit == fbyAddr.end()) { missing++; continue; }

		if (applyLuminaMetadata(fit->second, cit->second, stats)) {
			applied++;
		}
	}

	// Refresh the table to show updated names
	if (applied > 0) {
		refreshMetadata();
	}

	QString details;
	if (stats.namesApplied > 0) details += QString("%1 renamed, ").arg(stats.namesApplied);
	if (stats.functionCommentsApplied > 0) details += QString("%1 function comments, ").arg(stats.functionCommentsApplied);
	if (stats.functionTypesApplied > 0) details += QString("%1 function types, ").arg(stats.functionTypesApplied);
	if (stats.addressCommentsApplied > 0) details += QString("%1 address comments, ").arg(stats.addressCommentsApplied);
	if (stats.stackVariablesApplied > 0) details += QString("%1 stack vars, ").arg(stats.stackVariablesApplied);
	if (stats.tagsApplied > 0) details += QString("%1 tags, ").arg(stats.tagsApplied);
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
	LuminaApplyStats stats;

	for (const auto& [addr, cache] : m_pullCache) {
		if (!cache.have) { skipped++; continue; }
		auto fit = fbyAddr.find(addr);
		if (fit == fbyAddr.end()) { skipped++; continue; }

		if (applyLuminaMetadata(fit->second, cache, stats)) {
			applied++;
		}
	}

	// Refresh the table to show updated names
	if (applied > 0) {
		refreshMetadata();
	}

	QString details;
	if (stats.namesApplied > 0) details += QString("%1 renamed, ").arg(stats.namesApplied);
	if (stats.functionCommentsApplied > 0) details += QString("%1 function comments, ").arg(stats.functionCommentsApplied);
	if (stats.functionTypesApplied > 0) details += QString("%1 function types, ").arg(stats.functionTypesApplied);
	if (stats.addressCommentsApplied > 0) details += QString("%1 address comments, ").arg(stats.addressCommentsApplied);
	if (stats.stackVariablesApplied > 0) details += QString("%1 stack vars, ").arg(stats.stackVariablesApplied);
	if (stats.tagsApplied > 0) details += QString("%1 tags, ").arg(stats.tagsApplied);
	if (details.endsWith(", ")) details.chop(2);

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
		row.remoteComment = QString::fromStdString(buildMergedFunctionComment(cit->second.metadata));

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
		auto fit = fbyAddr.find(r.address);
		if (fit == fbyAddr.end()) continue;
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
			fprintf(stderr, "Function Address: 0x%llx\n", (unsigned long long)funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===");
			BinaryNinja::LogInfo("Function Address: 0x%llx", (unsigned long long)funcStart);
		}
		else
		{
			// Fallback to first function if no current function
			func = functions[0];
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===\n");
			fprintf(stderr, "Function Address: 0x%llx\n", (unsigned long long)funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===");
			BinaryNinja::LogInfo("Function Address: 0x%llx", (unsigned long long)funcStart);
		}
	}
	else
	{
		// Fallback to first function if no frame
		func = functions[0];
		funcStart = func->GetStart();
		fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===\n");
		fprintf(stderr, "Function Address: 0x%llx\n", (unsigned long long)funcStart);
		BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===");
		BinaryNinja::LogInfo("Function Address: 0x%llx", (unsigned long long)funcStart);
	}
	
	// 1. FUNCTION IDENTITY
	auto symbol = func->GetSymbol();
	std::string funcName = symbol ? symbol->GetFullName() : "<unnamed>";
	fprintf(stderr, "\n[1] FUNCTION IDENTITY:\n");
	fprintf(stderr, "  Name: %s\n", funcName.c_str());
	fprintf(stderr, "  Start: 0x%llx\n", (unsigned long long)funcStart);
	uint64_t funcSize = func->GetHighestAddress() - funcStart;
	fprintf(stderr, "  Size: %llu bytes (approx)\n", (unsigned long long)funcSize);
	
	BinaryNinja::LogInfo("[1] FUNCTION IDENTITY:");
	BinaryNinja::LogInfo("  Name: %s", funcName.c_str());
	BinaryNinja::LogInfo("  Start: 0x%llx", (unsigned long long)funcStart);
	BinaryNinja::LogInfo("  Size: %llu bytes (approx)", (unsigned long long)funcSize);
	
	// 2. FUNCTION TYPE INFO
	fprintf(stderr, "\n[2] FUNCTION TYPE INFO:\n");
	fprintf(stderr, "  No-return flag: %s\n", func->CanReturn() ? "false" : "true");
	BinaryNinja::LogInfo("[2] FUNCTION TYPE INFO:");
	BinaryNinja::LogInfo("  No-return flag: %s", func->CanReturn() ? "false" : "true");
	
	// 3. FUNCTION COMMENTS
	fprintf(stderr, "\n[3] FUNCTION COMMENTS:\n");
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
		fprintf(stderr, "    Block %zu: 0x%llx - 0x%llx (%llu bytes)\n",
		        i,
		        (unsigned long long)block->GetStart(),
		        (unsigned long long)block->GetEnd(),
		        (unsigned long long)blockSize);
		BinaryNinja::LogInfo("    Block %zu: 0x%llx - 0x%llx (%llu bytes)",
		        i,
		        (unsigned long long)block->GetStart(),
		        (unsigned long long)block->GetEnd(),
		        (unsigned long long)blockSize);
	}
	
	// 5. VARIABLES
	fprintf(stderr, "\n[5] STACK FRAME / VARIABLES:\n");
	auto vars = func->GetVariables();
	fprintf(stderr, "  Variable count: %zu\n", vars.size());
	BinaryNinja::LogInfo("[5] STACK FRAME / VARIABLES:");
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

	// 9. PUSH ENCODING STATUS
	fprintf(stderr, "\n[9] PUSH ENCODING STATUS:\n");
	fprintf(stderr, "  Push support is intentionally disabled in this plugin.\n");
	fprintf(stderr, "  Local Binary Ninja metadata is not serialized for Lumina upload.\n");
	BinaryNinja::LogInfo("[9] PUSH ENCODING STATUS:");
	BinaryNinja::LogInfo("  Push support is intentionally disabled in this plugin.");
	BinaryNinja::LogInfo("  Local Binary Ninja metadata is not serialized for Lumina upload.");

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
	size_t skippedCount = 0;

	for (auto& func : functions)
	{
		auto pullFilter = lumina::shouldSkipPull(bvRef, func);
		if (pullFilter.shouldSkip)
		{
			skippedCount++;
			BinaryNinja::LogDebug("[Lumina] Auto-query filter: skipping %s - %s",
				func->GetSymbol() ? func->GetSymbol()->GetShortName().c_str() : "<unnamed>",
				pullFilter.reason.c_str());
			continue;
		}

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

	if (skippedCount > 0)
	{
		BinaryNinja::LogInfo("[Lumina] Auto-query filter: skipped %zu function(s)", skippedCount);
	}

	BinaryNinja::LogInfo("[Lumina] Querying %zu functions from server %s:%d (TLS: %s)",
		hashes.size(),
		lumina::getHost().c_str(),
		lumina::getPort(),
		lumina::useTls() ? "yes" : "no");

	const auto hello = lumina::build_hello_request();
	const auto pull = lumina::build_pull_request(0, hashes);

	auto cli = createLuminaClient(nullptr);
	QString err;
	std::vector<lumina::OperationResult> statuses;
	std::vector<lumina::PulledFunction> pulledFuncs;

	int timeout = lumina::getTimeoutMs();
	if (!cli->helloAndPull(hello, pull, &err, &statuses, &pulledFuncs, timeout))
	{
		BinaryNinja::LogError("[Lumina] Auto-query failed: %s", err.toStdString().c_str());
		return;
	}

	// Apply results
	size_t fi = 0, applied = 0;
	LuminaApplyStats stats;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i)
	{
		if (statuses[i] == lumina::OperationResult::Ok && fi < pulledFuncs.size())
		{
			const auto& pf = pulledFuncs[fi++];
			FunctionRef func = funcRefs[i];

			FunctionMetadataSidebarWidget::PullCacheEntry cache;
			cache.have = true;
			cache.metadata = parsePulledMetadata(pf.data, func->GetStart());
			cache.popularity = pf.popularity;
			cache.len = pf.len;
			cache.remoteName = pf.name;
			cache.raw = pf.data;

			if (applyLuminaMetadata(func, cache, stats))
				applied++;
		}
	}

	BinaryNinja::LogInfo("[Lumina] ========================================");
	BinaryNinja::LogInfo(
		"[Lumina] Auto-query complete: %zu queried, %zu found, %zu applied (%zu names, %zu function comments, %zu function types, %zu address comments, %zu stack vars, %zu tags)",
		hashes.size(),
		pulledFuncs.size(),
		applied,
		stats.namesApplied,
		stats.functionCommentsApplied,
		stats.functionTypesApplied,
		stats.addressCommentsApplied,
		stats.stackVariablesApplied,
		stats.tagsApplied);
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
