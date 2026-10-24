import { render, screen } from '@testing-library/react'
import { createColumnHelper } from '@tanstack/react-table'
import { DataTable } from '@/components/DataTable'

type Row = { id: string; name: string }
const col = createColumnHelper<Row>()
const columns = [col.accessor('name', { header: 'Name' })]

test('renders rows and header', () => {
  render(<DataTable columns={columns} data={[{ id: '1', name: 'Alice' }]} />)
  expect(screen.getByText('Name')).toBeInTheDocument()
  expect(screen.getByText('Alice')).toBeInTheDocument()
})

test('shows "No data" when empty', () => {
  render(<DataTable columns={columns} data={[]} />)
  expect(screen.getByText(/no data/i)).toBeInTheDocument()
})

test('shows loading spinner when isLoading=true', () => {
  render(<DataTable columns={columns} data={[]} isLoading />)
  expect(screen.getByText(/loading/i)).toBeInTheDocument()
})
