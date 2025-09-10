import React, { useState, useEffect, useRef } from 'react';

interface NetworkNode {
  id: string;
  name: string;
  type: 'router' | 'switch' | 'server' | 'firewall' | 'unknown';
  ip: string;
  status: 'online' | 'offline' | 'degraded' | 'maintenance';
  x?: number;
  y?: number;
  connections?: string[];
  metrics?: {
    cpu?: number;
    memory?: number;
    uptime?: number;
  };
}

interface NetworkLink {
  source: string;
  target: string;
  type: 'ethernet' | 'fiber' | 'wireless';
  status: 'up' | 'down' | 'degraded';
  bandwidth?: number;
  latency?: number;
}

interface NetworkTopologyChartProps {
  nodes: NetworkNode[];
  links: NetworkLink[];
  selectedNode?: string;
  onNodeSelect?: (nodeId: string) => void;
  onNodeDoubleClick?: (nodeId: string) => void;
  showMetrics?: boolean;
  showLabels?: boolean;
  layout?: 'force' | 'hierarchical' | 'circular';
  width?: number;
  height?: number;
}

const NetworkTopologyChart: React.FC<NetworkTopologyChartProps> = ({
  nodes,
  links,
  selectedNode,
  onNodeSelect,
  onNodeDoubleClick,
  showMetrics = true,
  showLabels = true,
  layout = 'force',
  width = 800,
  height = 600
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [draggedNode, setDraggedNode] = useState<string | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Node colors based on status
  const getNodeColor = (status: string) => {
    switch (status) {
      case 'online': return '#10b981';
      case 'offline': return '#ef4444';
      case 'degraded': return '#f59e0b';
      case 'maintenance': return '#6b7280';
      default: return '#9ca3af';
    }
  };

  // Node colors based on type
  const getNodeTypeColor = (type: string) => {
    switch (type) {
      case 'router': return '#3b82f6';
      case 'switch': return '#8b5cf6';
      case 'server': return '#10b981';
      case 'firewall': return '#ef4444';
      default: return '#6b7280';
    }
  };

  // Link colors based on status
  const getLinkColor = (status: string) => {
    switch (status) {
      case 'up': return '#10b981';
      case 'down': return '#ef4444';
      case 'degraded': return '#f59e0b';
      default: return '#9ca3af';
    }
  };

  // Node shapes based on type
  const getNodeShape = (type: string) => {
    switch (type) {
      case 'router': return 'rect';
      case 'switch': return 'rect';
      case 'server': return 'circle';
      case 'firewall': return 'polygon';
      default: return 'circle';
    }
  };

  // Simple force-directed layout simulation
  const applyForceLayout = (nodes: NetworkNode[], links: NetworkLink[]) => {
    const nodeMap = new Map(nodes.map(node => [node.id, { ...node, x: node.x || Math.random() * width, y: node.y || Math.random() * height }]));
    
    // Simple force simulation
    for (let i = 0; i < 100; i++) {
      // Repulsion between all nodes
      for (const [id1, node1] of nodeMap) {
        for (const [id2, node2] of nodeMap) {
          if (id1 !== id2) {
            const dx = node1.x! - node2.x!;
            const dy = node1.y! - node2.y!;
            const distance = Math.sqrt(dx * dx + dy * dy);
            if (distance > 0) {
              const force = 1000 / (distance * distance);
              const fx = (dx / distance) * force;
              const fy = (dy / distance) * force;
              node1.x! -= fx * 0.01;
              node1.y! -= fy * 0.01;
            }
          }
        }
      }

      // Attraction for connected nodes
      for (const link of links) {
        const source = nodeMap.get(link.source);
        const target = nodeMap.get(link.target);
        if (source && target) {
          const dx = target.x! - source.x!;
          const dy = target.y! - source.y!;
          const distance = Math.sqrt(dx * dx + dy * dy);
          if (distance > 0) {
            const force = distance * 0.01;
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;
            source.x! += fx;
            source.y! += fy;
            target.x! -= fx;
            target.y! -= fy;
          }
        }
      }

      // Keep nodes within bounds
      for (const node of nodeMap.values()) {
        node.x = Math.max(50, Math.min(width - 50, node.x!));
        node.y = Math.max(50, Math.min(height - 50, node.y!));
      }
    }

    return Array.from(nodeMap.values());
  };

  // Apply layout
  const layoutedNodes = layout === 'force' 
    ? applyForceLayout(nodes, links)
    : nodes.map((node, index) => ({
        ...node,
        x: node.x || (layout === 'circular' ? width/2 + Math.cos(index * 2 * Math.PI / nodes.length) * 200 : Math.random() * width),
        y: node.y || (layout === 'circular' ? height/2 + Math.sin(index * 2 * Math.PI / nodes.length) * 200 : Math.random() * height)
      }));

  const handleMouseDown = (event: React.MouseEvent, nodeId: string) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (rect) {
      setDraggedNode(nodeId);
      setDragOffset({
        x: event.clientX - rect.left - (layoutedNodes.find(n => n.id === nodeId)?.x || 0),
        y: event.clientY - rect.top - (layoutedNodes.find(n => n.id === nodeId)?.y || 0)
      });
    }
  };

  const handleMouseMove = (event: React.MouseEvent) => {
    if (draggedNode && svgRef.current) {
      const rect = svgRef.current.getBoundingClientRect();
      const node = layoutedNodes.find(n => n.id === draggedNode);
      if (node) {
        node.x = event.clientX - rect.left - dragOffset.x;
        node.y = event.clientY - rect.top - dragOffset.y;
      }
    }
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
  };

  const handleNodeClick = (nodeId: string) => {
    onNodeSelect?.(nodeId);
  };

  const handleNodeDoubleClick = (nodeId: string) => {
    onNodeDoubleClick?.(nodeId);
  };

  return (
    <div className="bg-base-100 rounded-lg shadow-lg p-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-semibold">Network Topology</h3>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-success"></div>
            <span className="text-sm">Online</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-warning"></div>
            <span className="text-sm">Degraded</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-error"></div>
            <span className="text-sm">Offline</span>
          </div>
        </div>
      </div>

      <div className="border border-base-300 rounded-lg overflow-hidden">
        <svg
          ref={svgRef}
          width={width}
          height={height}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          className="cursor-move"
        >
          {/* Links */}
          {links.map((link, index) => {
            const sourceNode = layoutedNodes.find(n => n.id === link.source);
            const targetNode = layoutedNodes.find(n => n.id === link.target);
            
            if (!sourceNode || !targetNode) return null;

            return (
              <line
                key={index}
                x1={sourceNode.x}
                y1={sourceNode.y}
                x2={targetNode.x}
                y2={targetNode.y}
                stroke={getLinkColor(link.status)}
                strokeWidth={link.status === 'up' ? 2 : 1}
                strokeDasharray={link.status === 'degraded' ? '5,5' : 'none'}
                opacity={link.status === 'down' ? 0.3 : 1}
              />
            );
          })}

          {/* Nodes */}
          {layoutedNodes.map((node) => {
            const isSelected = selectedNode === node.id;
            const isHovered = hoveredNode === node.id;
            const nodeSize = isSelected ? 20 : isHovered ? 18 : 16;

            return (
              <g key={node.id}>
                {/* Node shape */}
                {getNodeShape(node.type) === 'circle' && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={nodeSize}
                    fill={getNodeColor(node.status)}
                    stroke={isSelected ? '#3b82f6' : getNodeTypeColor(node.type)}
                    strokeWidth={isSelected ? 3 : 2}
                    opacity={isHovered ? 0.8 : 1}
                    onMouseDown={(e) => handleMouseDown(e, node.id)}
                    onClick={() => handleNodeClick(node.id)}
                    onDoubleClick={() => handleNodeDoubleClick(node.id)}
                    onMouseEnter={() => setHoveredNode(node.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    className="cursor-pointer"
                  />
                )}

                {getNodeShape(node.type) === 'rect' && (
                  <rect
                    x={node.x! - nodeSize}
                    y={node.y! - nodeSize}
                    width={nodeSize * 2}
                    height={nodeSize * 2}
                    fill={getNodeColor(node.status)}
                    stroke={isSelected ? '#3b82f6' : getNodeTypeColor(node.type)}
                    strokeWidth={isSelected ? 3 : 2}
                    opacity={isHovered ? 0.8 : 1}
                    onMouseDown={(e) => handleMouseDown(e, node.id)}
                    onClick={() => handleNodeClick(node.id)}
                    onDoubleClick={() => handleNodeDoubleClick(node.id)}
                    onMouseEnter={() => setHoveredNode(node.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    className="cursor-pointer"
                  />
                )}

                {/* Node label */}
                {showLabels && (
                  <text
                    x={node.x}
                    y={node.y! + nodeSize + 15}
                    textAnchor="middle"
                    fontSize="12"
                    fill="#374151"
                    className="pointer-events-none"
                  >
                    {node.name}
                  </text>
                )}

                {/* Status indicator */}
                <circle
                  cx={node.x! + nodeSize - 4}
                  cy={node.y! - nodeSize + 4}
                  r={4}
                  fill={getNodeColor(node.status)}
                  stroke="#fff"
                  strokeWidth={1}
                />

                {/* Metrics overlay */}
                {showMetrics && node.metrics && isHovered && (
                  <g>
                    <rect
                      x={node.x! + nodeSize + 10}
                      y={node.y! - nodeSize}
                      width={120}
                      height={60}
                      fill="rgba(0, 0, 0, 0.8)"
                      rx={4}
                    />
                    <text
                      x={node.x! + nodeSize + 15}
                      y={node.y! - nodeSize + 15}
                      fontSize="10"
                      fill="white"
                    >
                      CPU: {node.metrics.cpu?.toFixed(1)}%
                    </text>
                    <text
                      x={node.x! + nodeSize + 15}
                      y={node.y! - nodeSize + 30}
                      fontSize="10"
                      fill="white"
                    >
                      Memory: {node.metrics.memory?.toFixed(1)}%
                    </text>
                    <text
                      x={node.x! + nodeSize + 15}
                      y={node.y! - nodeSize + 45}
                      fontSize="10"
                      fill="white"
                    >
                      Uptime: {node.metrics.uptime?.toFixed(0)}h
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className="mt-4 grid grid-cols-2 gap-4">
        <div>
          <h4 className="font-semibold mb-2">Node Types</h4>
          <div className="space-y-1 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-blue-500"></div>
              <span>Router</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-purple-500"></div>
              <span>Switch</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-green-500"></div>
              <span>Server</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded-full bg-red-500"></div>
              <span>Firewall</span>
            </div>
          </div>
        </div>

        <div>
          <h4 className="font-semibold mb-2">Connection Types</h4>
          <div className="space-y-1 text-sm">
            <div className="flex items-center gap-2">
              <div className="w-4 h-0.5 bg-green-500"></div>
              <span>Ethernet</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-0.5 bg-blue-500"></div>
              <span>Fiber</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-0.5 bg-yellow-500"></div>
              <span>Wireless</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkTopologyChart;
