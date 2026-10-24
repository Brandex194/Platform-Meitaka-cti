import { createBrowserRouter } from 'react-router-dom'

export const router = createBrowserRouter([
  { path: '/callback', element: <div>Callback</div> },
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
])
