import { describe, expect, it } from 'vitest';
import { safeCsvCell } from '../src/lib/utils';

describe('CSV export safety', () => {
  it.each(['=CMD()', '+SUM(1,1)', '-2+3', '@SUM(1+1)', '  =HYPERLINK("x")'])(
    'neutralizes spreadsheet formula %s',
    (value) => expect(safeCsvCell(value)).toBe(`'${value}`),
  );

  it('leaves ordinary values unchanged', () => {
    expect(safeCsvCell('critical finding')).toBe('critical finding');
  });
});
