#pragma once
#include <QtWidgets/QDialog>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <vector>

struct LuminaBulkDiffRow {
    uint64_t address = 0;
    QString  localName;
    QString  remoteName;
    QString  localComment;
    QString  remoteComment;

    // user selection
    bool     applyComment = false;
};

class LuminaBulkDiffDialog : public QDialog
{
    Q_OBJECT
public:
    explicit LuminaBulkDiffDialog(QWidget* parent,
                                  std::vector<LuminaBulkDiffRow> rows);

    // Returns rows with user selections applied.
    const std::vector<LuminaBulkDiffRow>& rows() const { return m_rows; }

private Q_SLOTS:
    void onAccept();
    void selectAll();
    void selectNone();
    void checkDiffOnly();

private:
    QTableWidget* m_table = nullptr;
    std::vector<LuminaBulkDiffRow> m_rows;

    void buildTable();
    static QString trunc(const QString& s);
};
