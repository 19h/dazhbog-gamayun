#include "ui/gamayun/gamayun.h"

#include "analysis/pattern_gen.h"
#include "fontsettings.h"

#include <QContextMenuEvent>
#include <QHeaderView>
#include <QMessageBox>
#include <QMenu>

#include <cstdio>
#include <string>

namespace {

constexpr int kSelectionColumnWidth = 30;
constexpr int kAddressColumnWidth = 100;
constexpr int kNameColumnWidth = 200;

}

// GamayunTableView implementation
GamayunTableView::GamayunTableView(QWidget* parent, ViewFrame* frame, BinaryViewRef data)
	: QTableView(parent), m_data(data), m_frame(frame)
{
	m_model = new GamayunModel(this, data);
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
	setColumnWidth(0, kSelectionColumnWidth);
	setColumnWidth(1, kAddressColumnWidth);
	setColumnWidth(2, kNameColumnWidth);
	
	updateFont();

	connect(this, &QTableView::doubleClicked, this, &GamayunTableView::onRowDoubleClicked);

	// Connect clicked signal to print CalcRel hash when a row is clicked
	connect(this, &QTableView::clicked, this, &GamayunTableView::onRowClicked);
}

void GamayunTableView::updateFont()
{
	setFont(getMonospaceFont(this));
}

void GamayunTableView::contextMenuEvent(QContextMenuEvent* event)
{
	QMenu menu(this);
	
	QModelIndex index = indexAt(event->pos());
	if (index.isValid())
	{
		menu.addAction("Navigate to Function", this, &GamayunTableView::navigateToFunction);
		menu.addAction("Apply Metadata", this, &GamayunTableView::applyMetadataToSelected);
	}
	
	menu.addAction("Refresh", [this]() { m_model->refresh(); });
	menu.addAction("Select All", [this]() { m_model->selectAll(); });
	menu.addAction("Select None", [this]() { m_model->selectNone(); });
	
	// Lumina operations
	menu.addSeparator();
	menu.addAction("Pull Selected (Lumina)", [this]() {
		auto p = qobject_cast<GamayunWidget*>(parentWidget());
		if (p) p->pullSelectedLumina();
	});
	menu.addAction("Pull All (Lumina)", [this]() {
		auto p = qobject_cast<GamayunWidget*>(parentWidget());
		if (p) p->pullAllLumina();
	});
	menu.addAction("Inspect Pulled Metadata", [this]() {
		auto p = qobject_cast<GamayunWidget*>(parentWidget());
		if (p) p->inspectPulledSelected();
	});
	menu.addAction("Log Pulled Metadata", [this]() {
		auto p = qobject_cast<GamayunWidget*>(parentWidget());
		if (p) p->logPulledSelected();
	});
	menu.addAction("Apply Pulled to Selected", [this]() {
		auto p = qobject_cast<GamayunWidget*>(parentWidget());
		if (p) p->applyPulledToSelected();
	});
	menu.addAction("Batch Diff & Apply (Lumina)", [this]() {
		auto p = qobject_cast<GamayunWidget*>(parentWidget());
		if (p) p->batchDiffAndApplySelected();
	});
	
	menu.exec(event->globalPos());
}

void GamayunTableView::onRowDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || !m_frame || !m_data)
		return;

	const auto& entry = m_model->entryAt(index.row());

	// Navigate to the function address
	m_frame->navigate(m_data, entry.address);
}

void GamayunTableView::onRowClicked(const QModelIndex& index)
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
		const std::string entryName = entry.name.toStdString();

		// Format hash as hex string
		char hashStr[33];
		for (int i = 0; i < 16; i++)
		{
			snprintf(hashStr + i * 2, 3, "%02x", pattern.hash[i]);
		}

		// Use LogAlert for visibility - shows in log with alert icon
		BinaryNinja::LogAlert("[Lumina] %s @ 0x%llx | CalcRel: %s | Size: %u bytes",
			entryName.c_str(),
			(unsigned long long)entry.address,
			hashStr,
			pattern.func_size);
	}
}

void GamayunTableView::applyMetadataToSelected()
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
	
	QMessageBox::information(this, "Gamayun",
		QString("Function: %1\nAddress: 0x%2\n\nMetadata:\n%3")
			.arg(entry.name)
			.arg(entry.address, 0, 16)
			.arg(metadataInfo.isEmpty() ? "No metadata" : metadataInfo));
}

void GamayunTableView::navigateToFunction()
{
	QModelIndex index = currentIndex();
	if (index.isValid())
		onRowDoubleClicked(index);
}
