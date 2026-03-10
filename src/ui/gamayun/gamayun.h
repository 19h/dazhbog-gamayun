#pragma once

#include <QtCore/QAbstractTableModel>
#include <QtCore/QString>
#include <QtCore/QVariant>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>

#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>

#include "binaryninjaapi.h"
#include "lumina/pulled_metadata.h"
#include "sidebarwidget.h"
#include "viewframe.h"

class QContextMenuEvent;

struct GamayunEntry
{
	uint64_t address;
	QString name;
	std::map<QString, QString> metadata;
	bool selected = false;
};

class GamayunModel : public QAbstractTableModel
{
	Q_OBJECT

	BinaryViewRef m_data;
	const std::unordered_map<uint64_t, lumina::PullCacheEntry>* m_pullCache = nullptr;
	std::vector<GamayunEntry> m_entries;

public:
	GamayunModel(QWidget* parent, BinaryViewRef data);

	void setBinaryView(BinaryViewRef data);
	void setPullCache(const std::unordered_map<uint64_t, lumina::PullCacheEntry>* pullCache);
	void notifyPullCacheChanged();
	void refresh();
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	virtual Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	GamayunEntry& entryAt(int row) { return m_entries[row]; }
	const GamayunEntry& entryAt(int row) const { return m_entries[row]; }

	void selectAll();
	void selectNone();
	std::vector<GamayunEntry*> getSelectedEntries();
};

class GamayunTableView : public QTableView
{
	Q_OBJECT

	BinaryViewRef m_data;
	ViewFrame* m_frame = nullptr;
	GamayunModel* m_model = nullptr;

public:
	GamayunTableView(QWidget* parent, ViewFrame* frame, BinaryViewRef data);

	void setContext(ViewFrame* frame, BinaryViewRef data);
	void updateFont();

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

private Q_SLOTS:
	void onRowDoubleClicked(const QModelIndex& index);
	void onRowClicked(const QModelIndex& index);
	void applyMetadataToSelected();
	void navigateToFunction();
};

class GamayunWidget : public SidebarWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	ViewFrame* m_frame = nullptr;
	GamayunTableView* m_table = nullptr;
	GamayunModel* m_model = nullptr;

	QPushButton* m_refreshButton = nullptr;
	QPushButton* m_pullSelected = nullptr;
	QPushButton* m_pullAll = nullptr;
	QPushButton* m_inspectPulled = nullptr;
	QPushButton* m_applyPulled = nullptr;
	QPushButton* m_applyPulledAll = nullptr;

	std::unordered_map<uint64_t, lumina::PullCacheEntry> m_pullCache;
	bool m_hasComputedInitialHashes = false;
	bool m_busy = false;

public:
	GamayunWidget(ViewFrame* frame, BinaryViewRef data);

	virtual void notifyViewChanged(ViewFrame* frame) override;
	virtual void notifyOffsetChanged(uint64_t offset) override;
	virtual void notifyFontChanged() override;

public Q_SLOTS:
	void refreshMetadata();
	void pullSelectedLumina();
	void pullAllLumina();
	void inspectPulledSelected();
	void logPulledSelected();
	void applyPulledToSelected();
	void applyPulledToAll();
	void batchDiffAndApplySelected();

private:
	void computeFunctionHashesForAllFunctions();
	void setBusyState(bool busy);
	bool ensureIdle(const QString& action);
};

class GamayunWidgetType : public SidebarWidgetType
{
public:
	GamayunWidgetType();

	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual SidebarContextSensitivity contextSensitivity() const override
	{
		return SelfManagedSidebarContext;
	}

	virtual SidebarWidgetLocation defaultLocation() const override
	{
		return RightContent;
	}
};
