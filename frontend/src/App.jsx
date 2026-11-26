import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import Landing from "./pages/Landing";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Investigation from "./pages/Investigation";
import Analysis from "./pages/Analysis";
import Result from "./pages/Result";
import { Forensics, Authentication, Intel, SMTP, Geo, Campaigns, Cases, Settings, Placeholder } from "./pages/DetailPages";
import History from "./pages/History";
import ThreatGraph from "./pages/ThreatGraph";
import EvidencePage from "./pages/EvidencePage";
import Reports from "./pages/Reports";
import IOCs from "./pages/IOCs";
import Summary from "./pages/Summary";
import CaseDetail from "./pages/CaseDetail";

export default function App(){
  return <BrowserRouter>
    <Routes>
      <Route path="/" element={<Landing/>}/>
      <Route path="/login" element={<Login/>}/>
      <Route element={<Layout/>}>
        <Route path="/dashboard" element={<Dashboard/>}/>
        <Route path="/investigate" element={<Investigation/>}/>
        <Route path="/analysis" element={<Analysis/>}/>
        <Route path="/result" element={<Result/>}/>
        <Route path="/forensics" element={<Forensics/>}/>
        <Route path="/authentication" element={<Authentication/>}/>
        <Route path="/intel" element={<Intel/>}/>
        <Route path="/smtp" element={<SMTP/>}/>
        <Route path="/graph" element={<ThreatGraph/>}/>
        <Route path="/geo" element={<Geo/>}/>
        <Route path="/campaigns" element={<Campaigns/>}/>
        <Route path="/evidence" element={<EvidencePage/>}/>
        <Route path="/cases" element={<Cases/>}/>
        <Route path="/cases/:id" element={<CaseDetail/>}/>
        <Route path="/history" element={<History/>}/>
        <Route path="/reports" element={<Reports/>}/>
        <Route path="/iocs" element={<IOCs/>}/>
        <Route path="/alerts" element={<Navigate to="/dashboard" replace/>}/>
        <Route path="/assistant" element={<Summary/>}/>
        <Route path="/settings" element={<Settings/>}/>
        <Route path="*" element={<Placeholder title="CyberLens Module"/>}/>
      </Route>
      <Route path="*" element={<Navigate to="/"/>}/>
    </Routes>
  </BrowserRouter>;
}
