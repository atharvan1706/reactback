// backend/models/Dashboard.js - ENHANCED WITH AXIS CONFIGURATIONS
import mongoose from 'mongoose';

const PanelSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { type: String, required: false },
  title: { type: String, required: true },
  vizType: String,
  dataSource: String,
  table: String,
  query: String,
  timestampField: String,
  yAxis: String,
  yAxes: [String],
  limit: Number,
  refreshInterval: Number,
  x: Number,
  y: Number,
  width: Number,
  height: Number,
  colors: [String],
  lineWidth: Number,
  fillOpacity: Number,
  showLegend: Boolean,
  showGrid: Boolean,
  showDots: Boolean,
  transformations: [mongoose.Schema.Types.Mixed],
  
  // Time and filter configurations
  timezone: { type: String, default: 'UTC' },
  yAxisScale: { type: String, default: 'auto' },
  yAxisMin: { type: String, default: '' },
  yAxisMax: { type: String, default: '' },
  xAxisScale: { type: String, default: 'auto' },
  timeRange: { type: String, default: 'all' },
  timeRangeLast: { type: String, default: '1h' },
  timeRangeStart: { type: String, default: '' },
  timeRangeEnd: { type: String, default: '' },
  filters: [mongoose.Schema.Types.Mixed],
  
  // ✅ NEW: Axis label configurations
  xAxisLabel: { type: String, default: '' },
  yAxisLabel: { type: String, default: '' },
  xAxisLabelRotation: { type: Number, default: 0 },
  yAxisLabelRotation: { type: Number, default: 0 },
  xAxisTickRotation: { type: Number, default: 0 },
  yAxisTickRotation: { type: Number, default: 0 },
  xAxisShowLabel: { type: Boolean, default: true },
  yAxisShowLabel: { type: Boolean, default: true },
  xAxisShowTicks: { type: Boolean, default: true },
  yAxisShowTicks: { type: Boolean, default: true },
  
  // ✅ NEW: Number formatting
  yAxisNumberFormat: { type: String, default: 'number' },
  yAxisDecimals: { type: Number, default: 2 },
  yAxisUnit: { type: String, default: '' },
  yAxisUnitPosition: { type: String, default: 'suffix' },
  yAxisCustomFormat: { type: String, default: '' },
  yAxisUseCommas: { type: Boolean, default: true },
  
  // ✅ NEW: Axis positioning
  yAxisWidth: { type: String, default: 'auto' },
  yAxisPosition: { type: String, default: 'left' },
  
  // ✅ NEW: Grid customization
  gridStrokeDashArray: { type: String, default: '3 3' },
  gridOpacity: { type: Number, default: 0.1 },
  
  // ✅ NEW: Tick customization
  xAxisTickCount: { type: String, default: 'auto' },
  yAxisTickCount: { type: String, default: 'auto' },
  xAxisTickInterval: { type: String, default: 'auto' },
  
  // ✅ NEW: Font sizes
  xAxisLabelFontSize: { type: Number, default: 12 },
  yAxisLabelFontSize: { type: Number, default: 12 },
  xAxisTickFontSize: { type: Number, default: 11 },
  yAxisTickFontSize: { type: Number, default: 11 },
  
  // SCADA specific fields
  scadaElements: [mongoose.Schema.Types.Mixed],
  scadaConnections: [mongoose.Schema.Types.Mixed],
  scadaConfig: mongoose.Schema.Types.Mixed
}, { _id: false });

const DashboardSchema = new mongoose.Schema({
  id: { 
    type: String, 
    required: true,
    unique: true,
    index: true
  },
  name: { 
    type: String, 
    required: true 
  },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  plantId: { 
    type: String, 
    required: true,
    index: true
  },
  panels: [PanelSchema],
  isDefault: { 
    type: Boolean, 
    default: false 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Auto-populate type from vizType if missing, then filter invalid panels
DashboardSchema.pre('validate', function() {
  this.updatedAt = new Date();
  
  if (this.panels && Array.isArray(this.panels)) {
    this.panels.forEach(panel => {
      if (panel && !panel.type && panel.vizType) {
        panel.type = 'chart';
        console.log(`✅ Auto-assigned type='chart' to panel: ${panel.id}`);
      }
      
      // ✅ Ensure ALL fields have defaults if missing
      if (panel.timezone === undefined) panel.timezone = 'UTC';
      if (panel.yAxisScale === undefined) panel.yAxisScale = 'auto';
      if (panel.yAxisMin === undefined) panel.yAxisMin = '';
      if (panel.yAxisMax === undefined) panel.yAxisMax = '';
      if (panel.xAxisScale === undefined) panel.xAxisScale = 'auto';
      if (panel.timeRange === undefined) panel.timeRange = 'all';
      if (panel.timeRangeLast === undefined) panel.timeRangeLast = '1h';
      if (panel.timeRangeStart === undefined) panel.timeRangeStart = '';
      if (panel.timeRangeEnd === undefined) panel.timeRangeEnd = '';
      if (panel.filters === undefined) panel.filters = [];
      
      // ✅ NEW: Axis configurations defaults
      if (panel.xAxisLabel === undefined) panel.xAxisLabel = '';
      if (panel.yAxisLabel === undefined) panel.yAxisLabel = '';
      if (panel.xAxisLabelRotation === undefined) panel.xAxisLabelRotation = 0;
      if (panel.yAxisLabelRotation === undefined) panel.yAxisLabelRotation = 0;
      if (panel.xAxisTickRotation === undefined) panel.xAxisTickRotation = 0;
      if (panel.yAxisTickRotation === undefined) panel.yAxisTickRotation = 0;
      if (panel.xAxisShowLabel === undefined) panel.xAxisShowLabel = true;
      if (panel.yAxisShowLabel === undefined) panel.yAxisShowLabel = true;
      if (panel.xAxisShowTicks === undefined) panel.xAxisShowTicks = true;
      if (panel.yAxisShowTicks === undefined) panel.yAxisShowTicks = true;
      if (panel.yAxisNumberFormat === undefined) panel.yAxisNumberFormat = 'number';
      if (panel.yAxisDecimals === undefined) panel.yAxisDecimals = 2;
      if (panel.yAxisUnit === undefined) panel.yAxisUnit = '';
      if (panel.yAxisUnitPosition === undefined) panel.yAxisUnitPosition = 'suffix';
      if (panel.yAxisCustomFormat === undefined) panel.yAxisCustomFormat = '';
      if (panel.yAxisUseCommas === undefined) panel.yAxisUseCommas = true;
      if (panel.yAxisWidth === undefined) panel.yAxisWidth = 'auto';
      if (panel.yAxisPosition === undefined) panel.yAxisPosition = 'left';
      if (panel.gridStrokeDashArray === undefined) panel.gridStrokeDashArray = '3 3';
      if (panel.gridOpacity === undefined) panel.gridOpacity = 0.1;
      if (panel.xAxisTickCount === undefined) panel.xAxisTickCount = 'auto';
      if (panel.yAxisTickCount === undefined) panel.yAxisTickCount = 'auto';
      if (panel.xAxisTickInterval === undefined) panel.xAxisTickInterval = 'auto';
      if (panel.xAxisLabelFontSize === undefined) panel.xAxisLabelFontSize = 12;
      if (panel.yAxisLabelFontSize === undefined) panel.yAxisLabelFontSize = 12;
      if (panel.xAxisTickFontSize === undefined) panel.xAxisTickFontSize = 11;
      if (panel.yAxisTickFontSize === undefined) panel.yAxisTickFontSize = 11;
    });
    
    // Filter out invalid panels
    const originalLength = this.panels.length;
    this.panels = this.panels.filter(panel => {
      const isValid = panel && panel.id && panel.title;
      if (!isValid) {
        console.warn('⚠️  Removing invalid panel:', JSON.stringify(panel));
      }
      return isValid;
    });
    
    if (this.panels.length !== originalLength) {
      console.log(`✅ Filtered panels: ${originalLength} -> ${this.panels.length}`);
    }
  }
});

// Compound index for user and plant queries
DashboardSchema.index({ userId: 1, plantId: 1 });

const Dashboard = mongoose.model('Dashboard', DashboardSchema);
export default Dashboard;
