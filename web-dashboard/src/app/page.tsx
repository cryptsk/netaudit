'use client'

import { useState, useEffect, useCallback } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  RefreshCw,
  Download,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle,
  XCircle,
  Server,
  Network,
  Lock,
  Terminal,
  FileJson,
  ChevronDown,
  ChevronRight,
  Activity,
  Scan,
  FileDown,
  Settings,
  Bug,
  Zap,
  Mail,
  Globe,
  ExternalLink
} from 'lucide-react'
import Image from 'next/image'

// Types
interface Finding {
  category: string
  check_name: string
  status: 'pass' | 'fail' | 'warning' | 'info'
  message: string
  severity: 'critical' | 'warning' | 'info'
  details: Record<string, unknown>
  recommendation: string
}

interface CategoryData {
  total: number
  passed: number
  failed: number
  warnings: number
  info: number
  critical_issues: number
  score: number
}

interface RiskBreakdown {
  critical: number
  warning: number
  info: number
  passed: number
}

interface Summary {
  total_checks: number
  passed: number
  failed: number
  warnings: number
  info: number
  risk_breakdown: RiskBreakdown
}

interface ScanResult {
  timestamp: string
  hostname: string
  overall_score: number
  grade: string
  categories: Record<string, CategoryData>
  findings: Finding[]
  summary: Summary
  recommendations: string[]
}

const API_BASE = '/api'

export default function NetAuditDashboard() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({})

  const runScan = useCallback(async (useCache = false) => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch(`${API_BASE}/scan?XTransformPort=3031&use_cache=${useCache}`)
      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }
      const data = await response.json()
      setScanResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }, [])

  const exportJson = useCallback(async () => {
    if (!scanResult) return
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cryptsk-netaudit-report-${scanResult.timestamp.split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [scanResult])

  const clearCacheAndScan = useCallback(async () => {
    try {
      await fetch(`${API_BASE}/scan/clear-cache?XTransformPort=3031`, { method: 'POST' })
      await runScan(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear cache')
    }
  }, [runScan])

  useEffect(() => {
    runScan(true)
  }, [runScan])

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A': return 'text-emerald-600'
      case 'B': return 'text-green-600'
      case 'C': return 'text-amber-600'
      case 'D': return 'text-orange-600'
      case 'F': return 'text-red-600'
      default: return 'text-gray-500'
    }
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-600'
    if (score >= 60) return 'text-amber-600'
    if (score >= 40) return 'text-orange-600'
    return 'text-red-600'
  }

  const getScoreBg = (score: number) => {
    if (score >= 80) return 'from-emerald-500 to-emerald-600'
    if (score >= 60) return 'from-amber-500 to-amber-600'
    if (score >= 40) return 'from-orange-500 to-orange-600'
    return 'from-red-500 to-red-600'
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pass': return <CheckCircle className="h-4 w-4 text-emerald-500" />
      case 'fail': return <XCircle className="h-4 w-4 text-red-500" />
      case 'warning': return <AlertTriangle className="h-4 w-4 text-amber-500" />
      default: return <Info className="h-4 w-4 text-slate-400" />
    }
  }

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <Badge className="bg-red-100 text-red-700 hover:bg-red-100 border-0 text-xs font-semibold">CRITICAL</Badge>
      case 'warning':
        return <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100 border-0 text-xs font-semibold">WARNING</Badge>
      default:
        return <Badge className="bg-slate-100 text-slate-600 hover:bg-slate-100 border-0 text-xs font-semibold">INFO</Badge>
    }
  }

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'sysctl': return <Terminal className="h-4 w-4" />
      case 'firewall': return <ShieldAlert className="h-4 w-4" />
      case 'network': return <Network className="h-4 w-4" />
      case 'security': return <Lock className="h-4 w-4" />
      default: return <Server className="h-4 w-4" />
    }
  }

  const toggleCategory = (category: string) => {
    setExpandedCategories(prev => ({
      ...prev,
      [category]: !prev[category]
    }))
  }

  const criticalFindings = scanResult?.findings.filter(f => f.severity === 'critical' && f.status !== 'pass') || []
  const warningFindings = scanResult?.findings.filter(f => f.severity === 'warning' && f.status !== 'pass') || []

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 flex flex-col">
      {/* Header */}
      <header className="sticky top-0 z-50 bg-white/80 backdrop-blur-xl border-b border-slate-200/80 shadow-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="absolute inset-0 bg-red-500 blur-xl opacity-20 rounded-2xl"></div>
                <div className="relative p-2 bg-white rounded-xl shadow-lg border border-slate-200">
                  <Image 
                    src="/logo.png" 
                    alt="CRYPTSK Logo" 
                    width={40} 
                    height={40}
                    className="rounded-lg"
                  />
                </div>
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-red-600 via-red-500 to-red-600 bg-clip-text text-transparent">
                  CRYPTSK NetAudit
                </h1>
                <p className="text-sm text-slate-500 font-medium">Linux Network Infrastructure Security Audit</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button
                variant="outline"
                size="default"
                onClick={() => runScan(false)}
                disabled={loading}
                className="bg-white hover:bg-slate-50 border-slate-200 shadow-sm"
              >
                {loading ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin text-red-500" />
                ) : (
                  <Scan className="h-4 w-4 mr-2 text-red-500" />
                )}
                Scan
              </Button>
              <Button
                variant="outline"
                size="default"
                onClick={clearCacheAndScan}
                disabled={loading}
                className="bg-white hover:bg-slate-50 border-slate-200 shadow-sm"
              >
                <Zap className="h-4 w-4 mr-2 text-amber-500" />
                Fresh Scan
              </Button>
              <Button
                size="default"
                onClick={exportJson}
                disabled={!scanResult || loading}
                className="bg-gradient-to-r from-red-500 to-red-600 hover:from-red-600 hover:to-red-700 text-white shadow-lg shadow-red-500/25 border-0"
              >
                <FileDown className="h-4 w-4 mr-2" />
                Export JSON
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 container mx-auto px-6 py-8">
        {error && (
          <Alert variant="destructive" className="mb-8 bg-red-50 border-red-200">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Error</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {loading && !scanResult ? (
          <div className="flex items-center justify-center h-96">
            <div className="text-center">
              <div className="relative inline-block">
                <div className="absolute inset-0 bg-red-500 blur-2xl opacity-20 rounded-full"></div>
                <div className="relative p-6 bg-white rounded-2xl shadow-xl border border-slate-200">
                  <RefreshCw className="h-10 w-10 animate-spin text-red-500 mx-auto" />
                </div>
              </div>
              <p className="mt-6 text-slate-600 font-medium">Running security audit...</p>
              <p className="text-sm text-slate-400 mt-1">Analyzing system configuration</p>
            </div>
          </div>
        ) : scanResult ? (
          <div className="space-y-8">
            {/* Score Overview */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Main Score Card */}
              <Card className="lg:col-span-4 bg-white border-slate-200 shadow-xl shadow-slate-200/50 overflow-hidden">
                <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${getScoreBg(scanResult.overall_score)}`}></div>
                <CardHeader className="pb-3 pt-6">
                  <CardTitle className="text-sm font-semibold text-slate-500 uppercase tracking-wider">Security Score</CardTitle>
                </CardHeader>
                <CardContent className="pb-6">
                  <div className="flex items-center justify-center py-4">
                    <div className="relative">
                      <div className="absolute inset-0 bg-red-500 blur-3xl opacity-10 rounded-full"></div>
                      <div className={`relative text-8xl font-bold tracking-tight ${getScoreColor(scanResult.overall_score)}`}>
                        {scanResult.overall_score}
                      </div>
                      <div className="text-center text-slate-400 text-sm font-medium mt-1">out of 100</div>
                    </div>
                    <div className="ml-8 pl-8 border-l border-slate-200">
                      <div className={`text-6xl font-bold ${getGradeColor(scanResult.grade)}`}>
                        {scanResult.grade}
                      </div>
                      <div className="text-sm text-slate-500 font-medium mt-1">Grade</div>
                    </div>
                  </div>
                  <div className="mt-6">
                    <Progress value={scanResult.overall_score} className="h-2 bg-slate-100" />
                  </div>
                </CardContent>
              </Card>

              {/* Risk Breakdown */}
              <Card className="lg:col-span-4 bg-white border-slate-200 shadow-xl shadow-slate-200/50">
                <CardHeader className="pb-3 pt-6">
                  <CardTitle className="text-sm font-semibold text-slate-500 uppercase tracking-wider">Risk Analysis</CardTitle>
                </CardHeader>
                <CardContent className="pb-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-3 rounded-xl bg-red-50 border border-red-100">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-red-500 rounded-lg">
                          <ShieldX className="h-4 w-4 text-white" />
                        </div>
                        <span className="font-semibold text-slate-700">Critical</span>
                      </div>
                      <span className="text-2xl font-bold text-red-600">{scanResult.summary.risk_breakdown.critical}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-xl bg-amber-50 border border-amber-100">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-amber-500 rounded-lg">
                          <AlertTriangle className="h-4 w-4 text-white" />
                        </div>
                        <span className="font-semibold text-slate-700">Warnings</span>
                      </div>
                      <span className="text-2xl font-bold text-amber-600">{scanResult.summary.risk_breakdown.warning}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-slate-400 rounded-lg">
                          <Info className="h-4 w-4 text-white" />
                        </div>
                        <span className="font-semibold text-slate-700">Info</span>
                      </div>
                      <span className="text-2xl font-bold text-slate-500">{scanResult.summary.risk_breakdown.info}</span>
                    </div>
                    <div className="flex items-center justify-between p-3 rounded-xl bg-emerald-50 border border-emerald-100">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-emerald-500 rounded-lg">
                          <ShieldCheck className="h-4 w-4 text-white" />
                        </div>
                        <span className="font-semibold text-slate-700">Passed</span>
                      </div>
                      <span className="text-2xl font-bold text-emerald-600">{scanResult.summary.risk_breakdown.passed}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* System Info */}
              <Card className="lg:col-span-4 bg-white border-slate-200 shadow-xl shadow-slate-200/50">
                <CardHeader className="pb-3 pt-6">
                  <CardTitle className="text-sm font-semibold text-slate-500 uppercase tracking-wider">System Details</CardTitle>
                </CardHeader>
                <CardContent className="pb-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Hostname</span>
                      <span className="font-mono text-sm bg-slate-100 px-3 py-1 rounded-lg text-slate-700">{scanResult.hostname}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Timestamp</span>
                      <span className="font-mono text-sm text-slate-700">{new Date(scanResult.timestamp).toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Total Checks</span>
                      <span className="font-bold text-slate-700">{scanResult.summary.total_checks}</span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-slate-100">
                      <span className="text-slate-500 font-medium">Passed</span>
                      <span className="font-bold text-emerald-600">{scanResult.summary.passed}</span>
                    </div>
                    <div className="flex items-center justify-between py-2">
                      <span className="text-slate-500 font-medium">Failed</span>
                      <span className="font-bold text-red-600">{scanResult.summary.failed}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Category Scores */}
            <Card className="bg-white border-slate-200 shadow-xl shadow-slate-200/50">
              <CardHeader className="pb-4">
                <CardTitle className="text-lg font-bold text-slate-800">Category Analysis</CardTitle>
                <CardDescription className="text-slate-500">Security score breakdown by category</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  {Object.entries(scanResult.categories).map(([name, data]) => (
                    <div 
                      key={name} 
                      className="relative p-5 rounded-2xl bg-gradient-to-br from-slate-50 to-white border border-slate-200 hover:border-red-200 hover:shadow-lg hover:shadow-red-100/50 transition-all duration-300 group"
                    >
                      <div className="flex items-center gap-2 mb-3">
                        <div className="p-2 bg-red-100 rounded-lg text-red-600 group-hover:bg-red-500 group-hover:text-white transition-colors">
                          {getCategoryIcon(name)}
                        </div>
                        <span className="font-semibold text-slate-700 capitalize">{name}</span>
                      </div>
                      <div className={`text-4xl font-bold mb-2 ${getScoreColor(data.score)}`}>
                        {data.score}
                        <span className="text-lg text-slate-400 font-normal">%</span>
                      </div>
                      <Progress value={data.score} className="h-1.5 bg-slate-100" />
                      <div className="flex items-center justify-between mt-3 text-sm">
                        <span className="text-slate-500">{data.passed}/{data.total} passed</span>
                        {data.critical_issues > 0 && (
                          <span className="text-red-500 font-semibold">{data.critical_issues} critical</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Tabs for Findings */}
            <Tabs defaultValue="critical" className="space-y-6">
              <TabsList className="bg-white border border-slate-200 p-1 shadow-sm">
                <TabsTrigger 
                  value="critical" 
                  className="gap-2 data-[state=active]:bg-red-500 data-[state=active]:text-white data-[state=active]:shadow-lg data-[state=active]:shadow-red-500/25"
                >
                  <ShieldX className="h-4 w-4" />
                  Critical ({criticalFindings.length})
                </TabsTrigger>
                <TabsTrigger 
                  value="warnings"
                  className="gap-2 data-[state=active]:bg-amber-500 data-[state=active]:text-white data-[state=active]:shadow-lg data-[state=active]:shadow-amber-500/25"
                >
                  <AlertTriangle className="h-4 w-4" />
                  Warnings ({warningFindings.length})
                </TabsTrigger>
                <TabsTrigger 
                  value="all"
                  className="gap-2 data-[state=active]:bg-slate-700 data-[state=active]:text-white"
                >
                  <FileJson className="h-4 w-4" />
                  All Findings
                </TabsTrigger>
                <TabsTrigger 
                  value="recommendations"
                  className="gap-2 data-[state=active]:bg-emerald-500 data-[state=active]:text-white data-[state=active]:shadow-lg data-[state=active]:shadow-emerald-500/25"
                >
                  <CheckCircle className="h-4 w-4" />
                  Recommendations
                </TabsTrigger>
              </TabsList>

              <TabsContent value="critical">
                <Card className="bg-white border-slate-200 shadow-xl shadow-slate-200/50">
                  <CardHeader className="border-b border-slate-100">
                    <CardTitle className="flex items-center gap-2 text-red-600">
                      <ShieldX className="h-5 w-5" />
                      Critical Issues
                    </CardTitle>
                    <CardDescription>Issues that require immediate attention</CardDescription>
                  </CardHeader>
                  <CardContent className="p-6">
                    {criticalFindings.length === 0 ? (
                      <div className="text-center py-12">
                        <div className="inline-flex p-4 rounded-full bg-emerald-100 mb-4">
                          <ShieldCheck className="h-8 w-8 text-emerald-600" />
                        </div>
                        <p className="text-slate-600 font-medium">No critical issues found!</p>
                        <p className="text-sm text-slate-400 mt-1">Your system security looks good</p>
                      </div>
                    ) : (
                      <ScrollArea className="h-96">
                        <div className="space-y-3 pr-4">
                          {criticalFindings.map((finding, index) => (
                            <div key={index} className="p-4 rounded-xl bg-red-50 border border-red-100 hover:border-red-200 transition-colors">
                              <div className="flex items-start justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  {getStatusIcon(finding.status)}
                                  <span className="font-semibold text-slate-800">{finding.check_name}</span>
                                </div>
                                <Badge className="bg-slate-100 text-slate-600 border-0 capitalize">{finding.category}</Badge>
                              </div>
                              <p className="text-sm text-slate-600 mb-3">{finding.message}</p>
                              {finding.recommendation && (
                                <div className="text-sm bg-white p-3 rounded-lg border border-red-100">
                                  <span className="font-semibold text-red-600">Fix:</span> <span className="text-slate-600">{finding.recommendation}</span>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="warnings">
                <Card className="bg-white border-slate-200 shadow-xl shadow-slate-200/50">
                  <CardHeader className="border-b border-slate-100">
                    <CardTitle className="flex items-center gap-2 text-amber-600">
                      <AlertTriangle className="h-5 w-5" />
                      Warnings
                    </CardTitle>
                    <CardDescription>Issues that should be reviewed</CardDescription>
                  </CardHeader>
                  <CardContent className="p-6">
                    {warningFindings.length === 0 ? (
                      <div className="text-center py-12">
                        <div className="inline-flex p-4 rounded-full bg-emerald-100 mb-4">
                          <CheckCircle className="h-8 w-8 text-emerald-600" />
                        </div>
                        <p className="text-slate-600 font-medium">No warnings found!</p>
                      </div>
                    ) : (
                      <ScrollArea className="h-96">
                        <div className="space-y-3 pr-4">
                          {warningFindings.map((finding, index) => (
                            <div key={index} className="p-4 rounded-xl bg-amber-50 border border-amber-100 hover:border-amber-200 transition-colors">
                              <div className="flex items-start justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  {getStatusIcon(finding.status)}
                                  <span className="font-semibold text-slate-800">{finding.check_name}</span>
                                </div>
                                <Badge className="bg-slate-100 text-slate-600 border-0 capitalize">{finding.category}</Badge>
                              </div>
                              <p className="text-sm text-slate-600 mb-3">{finding.message}</p>
                              {finding.recommendation && (
                                <div className="text-sm bg-white p-3 rounded-lg border border-amber-100">
                                  <span className="font-semibold text-amber-600">Fix:</span> <span className="text-slate-600">{finding.recommendation}</span>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="all">
                <Card className="bg-white border-slate-200 shadow-xl shadow-slate-200/50">
                  <CardHeader className="border-b border-slate-100">
                    <CardTitle className="text-slate-800">All Findings</CardTitle>
                    <CardDescription>Complete list of all check results</CardDescription>
                  </CardHeader>
                  <CardContent className="p-6">
                    <ScrollArea className="h-[500px]">
                      <div className="space-y-3 pr-4">
                        {Object.entries(scanResult.categories).map(([category, data]) => (
                          <div key={category} className="border border-slate-200 rounded-xl overflow-hidden">
                            <button
                              className="w-full p-4 flex items-center justify-between bg-slate-50 hover:bg-slate-100 transition-colors"
                              onClick={() => toggleCategory(category)}
                            >
                              <div className="flex items-center gap-3">
                                <div className="p-2 bg-red-100 rounded-lg text-red-600">
                                  {getCategoryIcon(category)}
                                </div>
                                <span className="font-semibold text-slate-700 capitalize">{category}</span>
                                <Badge className="bg-slate-200 text-slate-600 border-0">{data.total} checks</Badge>
                              </div>
                              <div className="flex items-center gap-4">
                                <div className={`text-xl font-bold ${getScoreColor(data.score)}`}>
                                  {data.score}%
                                </div>
                                {expandedCategories[category] ? (
                                  <ChevronDown className="h-5 w-5 text-slate-400" />
                                ) : (
                                  <ChevronRight className="h-5 w-5 text-slate-400" />
                                )}
                              </div>
                            </button>
                            {expandedCategories[category] && (
                              <div className="border-t border-slate-200">
                                {scanResult.findings
                                  .filter(f => f.category === category)
                                  .map((finding, index) => (
                                    <div key={index} className="p-4 border-b last:border-b-0 border-slate-100 hover:bg-slate-50 transition-colors">
                                      <div className="flex items-start gap-3">
                                        {getStatusIcon(finding.status)}
                                        <div className="flex-1">
                                          <div className="flex items-center gap-2 mb-1">
                                            <span className="font-medium text-slate-800">{finding.check_name}</span>
                                            {getSeverityBadge(finding.severity)}
                                          </div>
                                          <p className="text-sm text-slate-600">{finding.message}</p>
                                          {finding.recommendation && (
                                            <p className="text-sm text-red-600 mt-2 font-medium">{finding.recommendation}</p>
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                  ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="recommendations">
                <Card className="bg-white border-slate-200 shadow-xl shadow-slate-200/50">
                  <CardHeader className="border-b border-slate-100">
                    <CardTitle className="text-emerald-600">Recommendations</CardTitle>
                    <CardDescription>Prioritized list of security improvements</CardDescription>
                  </CardHeader>
                  <CardContent className="p-6">
                    {scanResult.recommendations.length === 0 ? (
                      <div className="text-center py-12">
                        <div className="inline-flex p-4 rounded-full bg-emerald-100 mb-4">
                          <CheckCircle className="h-8 w-8 text-emerald-600" />
                        </div>
                        <p className="text-slate-600 font-medium">No recommendations - system looks good!</p>
                      </div>
                    ) : (
                      <ScrollArea className="h-96">
                        <div className="space-y-3 pr-4">
                          {scanResult.recommendations.map((rec, index) => (
                            <div key={index} className="p-4 rounded-xl border border-slate-200 hover:border-red-200 hover:bg-red-50/30 transition-all flex items-start gap-4">
                              <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center text-white font-bold text-sm shadow-lg shadow-red-500/25">
                                {index + 1}
                              </div>
                              <p className="text-slate-700 pt-1">{rec}</p>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        ) : null}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 mt-auto">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Image 
                src="/logo.png" 
                alt="CRYPTSK" 
                width={28} 
                height={28}
                className="rounded"
              />
              <div className="text-sm">
                <span className="font-semibold text-slate-800">CRYPTSK NetAudit</span>
                <span className="text-slate-400 mx-2">|</span>
                <span className="text-slate-600">cryptsk pvt ltd</span>
                <span className="text-slate-400 mx-2">|</span>
                <span className="text-slate-500">v1.0.0</span>
              </div>
            </div>
            <div className="flex items-center gap-6 text-sm">
              <a 
                href="https://cryptsk.com" 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 text-slate-600 hover:text-red-500 transition-colors"
              >
                <Globe className="h-4 w-4" />
                cryptsk.com
                <ExternalLink className="h-3 w-3" />
              </a>
              <a 
                href="mailto:info@cryptsk.com"
                className="flex items-center gap-1.5 text-slate-600 hover:text-red-500 transition-colors"
              >
                <Mail className="h-4 w-4" />
                info@cryptsk.com
              </a>
            </div>
          </div>
          <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-400">
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1.5">
                <Lock className="h-3 w-3" />
                Read-only
              </span>
              <span className="flex items-center gap-1.5">
                <Bug className="h-3 w-3" />
                No auto-fix
              </span>
              <span className="flex items-center gap-1.5">
                <Settings className="h-3 w-3" />
                Safe execution
              </span>
            </div>
            <div className="text-slate-500">
              © 2025 CRYPTSK Pvt Ltd. All rights reserved.
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
