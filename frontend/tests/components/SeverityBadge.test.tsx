import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/SeverityBadge'

test.each([
  ['critical', 'bg-red-600'],
  ['high', 'bg-orange-500'],
  ['medium', 'bg-yellow-400'],
  ['low', 'bg-green-500'],
])('severity %s has correct color class', (severity, cls) => {
  const { container } = render(<SeverityBadge severity={severity} />)
  expect(container.firstChild).toHaveClass(cls)
  expect(screen.getByText(severity)).toBeInTheDocument()
})
