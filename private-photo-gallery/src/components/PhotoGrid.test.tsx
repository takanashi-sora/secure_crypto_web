import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { PhotoAssetStore } from '../lib/github';
import type { PhotoRecord } from '../types';
import { PhotoGrid } from './PhotoGrid';

const photo: PhotoRecord = {
  path: 'photos/sea.jpg',
  name: 'sea.jpg',
  sha: 'sha',
  size: 1024,
  title: '夏日海面',
};

const assets = {
  get: async () => ({ blob: new Blob(), url: 'blob:test' }),
} as unknown as PhotoAssetStore;

describe('PhotoGrid information hierarchy', () => {
  it('does not render empty metadata placeholders', () => {
    render(<PhotoGrid photos={[photo]} assets={assets} mode="archive" onOpen={vi.fn()} />);
    expect(screen.getByText('夏日海面')).toBeInTheDocument();
    expect(screen.queryByText(/未记录|未归入/)).not.toBeInTheDocument();
  });

  it('keeps organizing metadata out of editorial mode', () => {
    render(<PhotoGrid photos={[{ ...photo, location: '内浦', mood: '海风很好' }]} assets={assets} mode="editorial" onOpen={vi.fn()} />);
    expect(screen.queryByText('内浦')).not.toBeInTheDocument();
    expect(screen.queryByText('海风很好')).not.toBeInTheDocument();
  });
});
