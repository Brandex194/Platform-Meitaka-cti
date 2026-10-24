const COLORS: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-gray-900',
  low: 'bg-green-500 text-white',
  info: 'bg-blue-400 text-white',
}

export function RiskLevelBadge({ level }: { level: string }) {
  const cls = COLORS[level.toLowerCase()] ?? 'bg-gray-400 text-white'
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
      {level}
    </span>
  )
}
