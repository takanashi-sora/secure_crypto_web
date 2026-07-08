export function formatBytes(bytes: number) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function displayDate(value?: string) {
  if (!value) return '日期未记录';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(date);
}

export function safeFileName(name: string) {
  const dot = name.lastIndexOf('.');
  const extension = dot >= 0 ? name.slice(dot).toLowerCase().replace(/[^a-z0-9.]/g, '') : '.jpg';
  const base = (dot >= 0 ? name.slice(0, dot) : name)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 70) || 'photo';
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  const random = crypto.getRandomValues(new Uint32Array(1))[0].toString(36).slice(0, 6);
  return `${stamp}-${random}-${base}${extension}`;
}
