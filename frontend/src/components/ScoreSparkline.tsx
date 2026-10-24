import { LineChart, Line, ResponsiveContainer, Tooltip } from 'recharts'

export function ScoreSparkline({ data }: { data: { computed_at: string; value: number }[] }) {
  return (
    <ResponsiveContainer width="100%" height={40}>
      <LineChart data={data}>
        <Line type="monotone" dataKey="value" stroke="#3b82f6" dot={false} strokeWidth={2} />
        <Tooltip formatter={(v: number) => v.toFixed(3)} />
      </LineChart>
    </ResponsiveContainer>
  )
}
