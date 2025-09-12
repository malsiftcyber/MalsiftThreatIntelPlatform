import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Toaster } from 'react-hot-toast';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Indicators from './pages/Indicators';
import Sources from './pages/Sources';
import Feeds from './pages/Feeds';
import Campaigns from './pages/Campaigns';
import DarkWeb from './pages/DarkWeb';
import Jobs from './pages/Jobs';
import Exclusions from './pages/Exclusions';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="indicators" element={<Indicators />} />
            <Route path="feeds" element={<Feeds />} />
            <Route path="sources" element={<Sources />} />
            <Route path="campaigns" element={<Campaigns />} />
            <Route path="darkweb" element={<DarkWeb />} />
            <Route path="jobs" element={<Jobs />} />
            <Route path="exclusions" element={<Exclusions />} />
          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  );
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/indicators" element={<Indicators />} />
            <Route path="/sources" element={<Sources />} />
            <Route path="/feeds" element={<Feeds />} />
            <Route path="/campaigns" element={<Campaigns />} />
            <Route path="/darkweb" element={<DarkWeb />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/exclusions" element={<Exclusions />} />
          </Routes>
        </Layout>
        <Toaster position="top-right" />
      </Router>
    </QueryClientProvider>
  );
}

export default App;
