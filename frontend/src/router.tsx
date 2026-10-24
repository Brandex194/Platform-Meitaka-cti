import { createBrowserRouter } from 'react-router-dom'
import { AuthGuard } from './auth/AuthGuard'
import { Callback } from './auth/Callback'

export const router = createBrowserRouter([
  { path: '/callback', element: <Callback /> },
  {
    element: <AuthGuard />,
    children: [
      { path: '/', element: <div>Dashboard</div> },
      { path: '/assets', element: <div>Assets</div> },
      { path: '/scores', element: <div>Scores</div> },
      { path: '/exposure', element: <div>Exposure</div> },
      { path: '/analysis', element: <div>Analysis</div> },
      { path: '/cases', element: <div>Cases</div> },
      { path: '/actors', element: <div>Actors</div> },
      { path: '/campaigns', element: <div>Campaigns</div> },
      { path: '/observables', element: <div>Observables</div> },
      { path: '/dark-web', element: <div>DarkWeb</div> },
      { path: '/reports', element: <div>Reports</div> },
    ],
  },
])
