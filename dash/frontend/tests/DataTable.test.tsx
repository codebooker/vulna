import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DataTable, type ColumnDef } from '../src/components/app/data-table';
import { downloadCsv } from '../src/lib/utils';

vi.mock('../src/lib/utils', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/lib/utils')>();
  return { ...original, downloadCsv: vi.fn() };
});

interface Row {
  id: string;
  label: string;
}

const columns: ColumnDef<Row>[] = [
  {
    id: 'label',
    header: 'Label',
    cell: (row) => row.label,
    csvValue: (row) => row.label,
  },
  {
    id: 'id',
    header: 'Stable ID',
    defaultHidden: true,
    cell: (row) => row.id,
    csvValue: (row) => row.id,
  },
];

describe('DataTable exports', () => {
  beforeEach(() => vi.mocked(downloadCsv).mockClear());

  it('can export hidden identity columns without displaying them', () => {
    render(
      <DataTable
        columns={columns}
        rows={[{ id: 'asset-1', label: 'gateway' }]}
        rowKey={(row) => row.id}
        exportName="assets"
        exportAllColumns
      />,
    );

    expect(screen.queryByText('Stable ID')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Export' }));

    expect(downloadCsv).toHaveBeenCalledWith(
      'assets.csv',
      ['Label', 'Stable ID'],
      [['gateway', 'asset-1']],
    );
  });
});
