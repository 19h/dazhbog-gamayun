#include "ui/gamayun/gamayun.h"

#include <QStringList>

#include <string>

namespace {

constexpr int kSelectionColumn = 0;
constexpr int kAddressColumn = 1;
constexpr int kNameColumn = 2;
constexpr int kMetadataColumn = 3;
constexpr int kColumnCount = 4;

QString summarizeLocalMetadata(const GamayunEntry& entry)
{
	QStringList parts;
	for (auto it = entry.metadata.begin(); it != entry.metadata.end(); ++it)
		parts << it->first;
	return parts.join(", ");
}

QString summarizePulledMetadata(const lumina::PullCacheEntry& cacheEntry)
{
	QStringList parts;
	parts << QString("pulled");
	if (!cacheEntry.remoteName.empty())
		parts << QString::fromStdString(cacheEntry.remoteName);
	parts << QString("%1 item(s)").arg(cacheEntry.metadata.componentCount());
	if (!cacheEntry.metadata.ok())
		parts << QString("parse issues: %1").arg(cacheEntry.metadata.errors.size());
	return parts.join(", ");
}

}

// GamayunModel implementation
GamayunModel::GamayunModel(QWidget* parent, BinaryViewRef data)
	: QAbstractTableModel(parent), m_data(data)
{
	refresh();
}

void GamayunModel::setPullCache(const std::unordered_map<uint64_t, lumina::PullCacheEntry>* pullCache)
{
	m_pullCache = pullCache;
	notifyPullCacheChanged();
}

void GamayunModel::notifyPullCacheChanged()
{
	if (m_entries.empty())
		return;

	emit dataChanged(
		createIndex(0, kMetadataColumn),
		createIndex(static_cast<int>(m_entries.size()) - 1, kMetadataColumn));
}

void GamayunModel::refresh()
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
		GamayunEntry entry;
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

		(void)hasMetadata;
		m_entries.push_back(entry);
	}
	
	endResetModel();
}

int GamayunModel::columnCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return kColumnCount;
}

int GamayunModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return static_cast<int>(m_entries.size());
}

QVariant GamayunModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return QVariant();
	
	const auto& entry = m_entries[index.row()];
	
	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case kSelectionColumn:
			return QVariant();
		case kAddressColumn:
			return QString("0x%1").arg(entry.address, 0, 16);
		case kNameColumn:
			return entry.name;
		case kMetadataColumn:
			{
				QStringList summaries;
				const QString localSummary = summarizeLocalMetadata(entry);
				if (!localSummary.isEmpty())
					summaries << localSummary;

				if (m_pullCache != nullptr)
				{
					auto it = m_pullCache->find(entry.address);
					if (it != m_pullCache->end() && it->second.have)
						summaries << summarizePulledMetadata(it->second);
				}

				return summaries.join(" | ");
			}
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == kSelectionColumn)
	{
		return entry.selected ? Qt::Checked : Qt::Unchecked;
	}
	else if (role == Qt::TextAlignmentRole && index.column() == kAddressColumn)
	{
		return QVariant(Qt::AlignRight | Qt::AlignVCenter);
	}
	
	return QVariant();
}

QVariant GamayunModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch (section)
		{
		case kSelectionColumn: return "✓";
		case kAddressColumn: return "Address";
		case kNameColumn: return "Function Name";
		case kMetadataColumn: return "Metadata";
		}
	}
	return QVariant();
}

Qt::ItemFlags GamayunModel::flags(const QModelIndex& index) const
{
	if (!index.isValid())
		return Qt::NoItemFlags;
	
	Qt::ItemFlags flags = QAbstractTableModel::flags(index);
	
	if (index.column() == kSelectionColumn)
		flags |= Qt::ItemIsUserCheckable;
	
	return flags;
}

bool GamayunModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return false;
	
	if (role == Qt::CheckStateRole && index.column() == kSelectionColumn)
	{
		m_entries[index.row()].selected = (value.toInt() == Qt::Checked);
		emit dataChanged(index, index);
		return true;
	}
	
	return false;
}

void GamayunModel::selectAll()
{
	for (auto& entry : m_entries)
		entry.selected = true;
	if (!m_entries.empty())
		emit dataChanged(createIndex(0, kSelectionColumn), createIndex(int(m_entries.size()) - 1, kSelectionColumn));
}

void GamayunModel::selectNone()
{
	for (auto& entry : m_entries)
		entry.selected = false;
	if (!m_entries.empty())
		emit dataChanged(createIndex(0, kSelectionColumn), createIndex(int(m_entries.size()) - 1, kSelectionColumn));
}

std::vector<GamayunEntry*> GamayunModel::getSelectedEntries()
{
	std::vector<GamayunEntry*> selected;
	for (auto& entry : m_entries)
	{
		if (entry.selected)
			selected.push_back(&entry);
	}
	return selected;
}
