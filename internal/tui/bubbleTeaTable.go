// Package tui contains some tui components.
package tui

import (
	"errors"
	"fmt"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var ErrUserQuit = errors.New("user quit")

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type TableColumn struct {
	Title string
	Width int
}

type TableRow []string

// GetTableSelection displays a table and allows the user to select a row.
// The function returns the identifier of the selected row as a string whose column is identified by idenifierColumnIndex,
// or an error if something goes wrong or the user quits.
// If the user quits the table selection, ErrUserQuit is returned.
func GetTableSelection(rows []TableRow, cols []TableColumn, idenifierColumnIndex int) (string, error) {
	tableColumns := make([]table.Column, 0, len(cols))

	for _, col := range cols {
		tableColumns = append(tableColumns, table.Column{
			Title: col.Title,
			Width: col.Width,
		})
	}

	tableRows := make([]table.Row, 0, len(rows))
	for _, row := range rows {
		tableRows = append(tableRows, []string(row))
	}

	m, err := setUpTable(tableColumns, tableRows, idenifierColumnIndex)
	if err != nil {
		return "", err
	}
	returnedModel, err := tea.NewProgram(m).Run()
	if err != nil {
		return "", err
	}

	finalModel, ok := returnedModel.(model)
	if !ok {
		return "", fmt.Errorf("could not get interface")
	}
	if finalModel.userQuit {
		return "", ErrUserQuit
	}

	return finalModel.selectedRowID, nil
}

type model struct {
	table table.Model
	// selectedRowID is to identify which row was chosen when the final model is returned.
	selectedRowID string
	// identifierColumn is to determine which column will be used to set the selectedRowID
	identifierColumn int
	// userQuit is to signal that the user did not select any row but just quit!
	userQuit bool
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			m.userQuit = true
			return m, tea.Quit
		case "enter":
			m.selectedRowID = m.table.SelectedRow()[m.identifierColumn]
			return m, tea.Quit
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m model) View() tea.View {
	return tea.NewView(baseStyle.Render(m.table.View()) + "\n  " + m.table.HelpView() + "\n")
}

func setUpTable(columns []table.Column, rows []table.Row, idenifierIndex int) (tea.Model, error) {
	if len(columns) == 0 {
		return nil, fmt.Errorf("table columns empty")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("table rows empty")
	}

	tableHeight := min(len(rows)+2, 10)
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(tableHeight),
		table.WithWidth(tableWidth(columns)),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	if idenifierIndex >= len(rows[0]) {
		return nil, fmt.Errorf("invalid identifier index")
	}

	m := model{
		table:            t,
		identifierColumn: idenifierIndex,
		selectedRowID:    rows[0][idenifierIndex],
	}

	return m, nil
}

func tableWidth(columns []table.Column) int {
	width := 0
	for _, col := range columns {
		width += col.Width
	}
	return width
}
