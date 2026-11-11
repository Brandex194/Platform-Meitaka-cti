import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/SeverityBadge'

test.each([
  ['critical', 'badge-critical'],
  ['high', 'badge-high'],
  ['medium', 'badge-medium'],
  ['low', 'badge-low'],
])('severity %s has correct color class', (severity, cls) => {
  const { container } = render(<SeverityBadge severity={severity} />)
  expect(container.firstChild).toHaveClass(cls)
  expect(screen.getByText(severity)).toBeInTheDocument()
})
