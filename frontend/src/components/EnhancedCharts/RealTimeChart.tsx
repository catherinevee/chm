import React, { useState, useEffect, useRef } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart, ReferenceLine } from 'recharts';

interface DataPoint {
  timestamp: string;
  value: number;
  unit?: string;
  quality_score?: number;
}

interface RealTimeChartProps {
  data: DataPoint[];
  title: string;
  metricType: string;
  unit?: string;
  threshold?: {
    warning: number;
    critical: number;
  };
  height?: number;
  showArea?: boolean;
  showThresholds?: boolean;
  updateInterval?: number;
  maxDataPoints?: number;
}

const RealTimeChart: React.FC<RealTimeChartProps> = ({
  data,
  title,
  metricType,
  unit = '',
  threshold,
  height = 300,
  showArea = true,
  showThresholds = true,
  updateInterval = 5000,
  maxDataPoints = 100
}) => {
  const [chartData, setChartData] = useState<DataPoint[]>([]);
  const [isRealTime, setIsRealTime] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    // Limit data points for performance
    const limitedData = data.slice(-maxDataPoints);
    setChartData(limitedData);
  }, [data, maxDataPoints]);

  useEffect(() => {
    if (isRealTime && updateInterval > 0) {
      intervalRef.current = setInterval(() => {
        // In a real implementation, this would fetch new data
        // For now, we'll simulate real-time updates
        setChartData(prevData => {
          const newData = [...prevData];
          if (newData.length >= maxDataPoints) {
            newData.shift();
          }
          return newData;
        });
      }, updateInterval);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isRealTime, updateInterval, maxDataPoints]);

  const getMetricColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'cpu': return '#3b82f6';
      case 'memory': return '#10b981';
      case 'disk': return '#8b5cf6';
      case 'network': return '#f59e0b';
      case 'temperature': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const formatTooltipValue = (value: number, unit: string) => {
    if (unit === '%') return `${value.toFixed(1)}%`;
    if (unit === 'MB') return `${(value / 1024 / 1024).toFixed(2)} MB`;
    if (unit === 'Mbps') return `${value.toFixed(2)} Mbps`;
    if (unit === 'ms') return `${value.toFixed(2)} ms`;
    if (unit === '°C') return `${value.toFixed(1)}°C`;
    return value.toFixed(2);
  };

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-base-100 border border-base-300 rounded-lg p-3 shadow-lg">
          <p className="font-semibold">{new Date(label).toLocaleString()}</p>
          <p className="text-sm">
            <span className="font-medium" style={{ color: payload[0].color }}>
              {title}:
            </span>{' '}
            {formatTooltipValue(data.value, unit)}
          </p>
          {data.quality_score && (
            <p className="text-xs text-base-content/60">
              Quality: {(data.quality_score * 100).toFixed(1)}%
            </p>
          )}
        </div>
      );
    }
    return null;
  };

  const renderChart = () => {
    if (showArea) {
      return (
        <AreaChart data={chartData} height={height}>
          <defs>
            <linearGradient id={`gradient-${metricType}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={getMetricColor(metricType)} stopOpacity={0.3}/>
              <stop offset="95%" stopColor={getMetricColor(metricType)} stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis 
            dataKey="timestamp" 
            tickFormatter={(value) => new Date(value).toLocaleTimeString()}
            stroke="#9ca3af"
          />
          <YAxis 
            tickFormatter={(value) => formatTooltipValue(value, unit)}
            stroke="#9ca3af"
          />
          <Tooltip content={<CustomTooltip />} />
          <Area
            type="monotone"
            dataKey="value"
            stroke={getMetricColor(metricType)}
            strokeWidth={2}
            fill={`url(#gradient-${metricType})`}
            dot={{ fill: getMetricColor(metricType), strokeWidth: 2, r: 4 }}
            activeDot={{ r: 6, stroke: getMetricColor(metricType), strokeWidth: 2 }}
          />
          {showThresholds && threshold && (
            <>
              <ReferenceLine 
                y={threshold.warning} 
                stroke="#f59e0b" 
                strokeDasharray="5 5" 
                label={{ value: "Warning", position: "topRight" }}
              />
              <ReferenceLine 
                y={threshold.critical} 
                stroke="#ef4444" 
                strokeDasharray="5 5" 
                label={{ value: "Critical", position: "topRight" }}
              />
            </>
          )}
        </AreaChart>
      );
    } else {
      return (
        <LineChart data={chartData} height={height}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis 
            dataKey="timestamp" 
            tickFormatter={(value) => new Date(value).toLocaleTimeString()}
            stroke="#9ca3af"
          />
          <YAxis 
            tickFormatter={(value) => formatTooltipValue(value, unit)}
            stroke="#9ca3af"
          />
          <Tooltip content={<CustomTooltip />} />
          <Line
            type="monotone"
            dataKey="value"
            stroke={getMetricColor(metricType)}
            strokeWidth={2}
            dot={{ fill: getMetricColor(metricType), strokeWidth: 2, r: 4 }}
            activeDot={{ r: 6, stroke: getMetricColor(metricType), strokeWidth: 2 }}
          />
          {showThresholds && threshold && (
            <>
              <ReferenceLine 
                y={threshold.warning} 
                stroke="#f59e0b" 
                strokeDasharray="5 5" 
                label={{ value: "Warning", position: "topRight" }}
              />
              <ReferenceLine 
                y={threshold.critical} 
                stroke="#ef4444" 
                strokeDasharray="5 5" 
                label={{ value: "Critical", position: "topRight" }}
              />
            </>
          )}
        </LineChart>
      );
    }
  };

  return (
    <div className="bg-base-100 rounded-lg shadow-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold">{title}</h3>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2">
            <div 
              className="w-3 h-3 rounded-full" 
              style={{ backgroundColor: getMetricColor(metricType) }}
            ></div>
            <span className="text-sm text-base-content/60">{metricType.toUpperCase()}</span>
          </div>
          <button
            className={`btn btn-sm ${isRealTime ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setIsRealTime(!isRealTime)}
          >
            {isRealTime ? 'Live' : 'Static'}
          </button>
        </div>
      </div>
      
      <div className="mb-2">
        <div className="flex justify-between text-sm text-base-content/60">
          <span>Data Points: {chartData.length}</span>
          <span>Update: {updateInterval / 1000}s</span>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={height}>
        {renderChart()}
      </ResponsiveContainer>

      {chartData.length > 0 && (
        <div className="mt-4 grid grid-cols-3 gap-4 text-center">
          <div>
            <div className="text-sm text-base-content/60">Current</div>
            <div className="font-semibold">
              {formatTooltipValue(chartData[chartData.length - 1]?.value || 0, unit)}
            </div>
          </div>
          <div>
            <div className="text-sm text-base-content/60">Average</div>
            <div className="font-semibold">
              {formatTooltipValue(
                chartData.reduce((sum, point) => sum + point.value, 0) / chartData.length,
                unit
              )}
            </div>
          </div>
          <div>
            <div className="text-sm text-base-content/60">Peak</div>
            <div className="font-semibold">
              {formatTooltipValue(
                Math.max(...chartData.map(point => point.value)),
                unit
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RealTimeChart;
