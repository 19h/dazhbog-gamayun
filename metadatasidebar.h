#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QTableView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QMenu>
#include <map>
#include <unordered_map>
#include "binaryninjaapi.h"
#include "sidebarwidget.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "theme.h"
#include "lumina_client.h"
#include "lumina_metadata.h"
#include "bulkdiffdialog.h"

using namespace BinaryNinja;

// Structure to hold function metadata info
struct FunctionMetadataEntry
{
	uint64_t address;
	QString name;
	std::map<QString, QString> metadata;
	bool selected = false;
};

// Table model for displaying function metadata
class FunctionMetadataModel : public QAbstractTableModel
{
	Q_OBJECT

	BinaryViewRef m_data;
	std::vector<FunctionMetadataEntry> m_entries;

public:
	FunctionMetadataModel(QWidget* parent, BinaryViewRef data);

	void refresh();
	
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
	virtual Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

	FunctionMetadataEntry& entryAt(int row) { return m_entries[row]; }
	const FunctionMetadataEntry& entryAt(int row) const { return m_entries[row]; }
	
	void selectAll();
	void selectNone();
	std::vector<FunctionMetadataEntry*> getSelectedEntries();
};

// Table view for function metadata
class FunctionMetadataTableView : public QTableView
{
	Q_OBJECT

	BinaryViewRef m_data;
	ViewFrame* m_frame;
	FunctionMetadataModel* m_model;
	UIActionHandler m_actionHandler;

public:
	FunctionMetadataTableView(QWidget* parent, ViewFrame* frame, BinaryViewRef data);

	void updateFont();

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

private Q_SLOTS:
	void onRowDoubleClicked(const QModelIndex& index);
	void onRowClicked(const QModelIndex& index);
	void applyMetadataToSelected();
	void navigateToFunction();
};

// Main sidebar widget
class FunctionMetadataSidebarWidget : public SidebarWidget
{
	Q_OBJECT

	BinaryViewRef m_data;
	ViewFrame* m_frame;
	FunctionMetadataTableView* m_table;
	FunctionMetadataModel* m_model;
	
	QPushButton* m_refreshButton;
	QPushButton* m_rejectAllButton;
	QPushButton* m_applySelectedButton;
	QPushButton* m_applyAllButton;
	QPushButton* m_pullSelected;
	QPushButton* m_pullAll;
	QPushButton* m_inspectPulled;
	QPushButton* m_applyPulled;
	QPushButton* m_applyPulledAll;

public:
	// Cache pulled Lumina metadata per function start address.
	struct PullCacheEntry {
		bool have = false;
		lumina::FunctionMetadata metadata;
		uint32_t popularity = 0;
		uint32_t len = 0;
		std::string remoteName;
		std::vector<uint8_t> raw;
	};

private:
	std::unordered_map<uint64_t, PullCacheEntry> m_pullCache;

	// Track if we've computed CalcRel for all functions after initial analysis
	bool m_hasComputedInitialCalcRel = false;

public:
	FunctionMetadataSidebarWidget(ViewFrame* frame, BinaryViewRef data);

	virtual void notifyViewChanged(ViewFrame* frame) override;
	virtual void notifyOffsetChanged(uint64_t offset) override;
	virtual void notifyFontChanged() override;

public Q_SLOTS:
	void refreshMetadata();
	void rejectAll();
	void applySelected();
	void applyAll();
	void pullSelectedLumina();
	void pullAllLumina();
	void inspectPulledSelected();
	void logPulledSelected();
	void applyPulledToSelected();
	void applyPulledToAll();
	void batchDiffAndApplySelected();

private:
	void computeCalcRelForAllFunctions();
};

// Sidebar widget type for registration
class FunctionMetadataSidebarWidgetType : public SidebarWidgetType
{
public:
	FunctionMetadataSidebarWidgetType();
	
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
