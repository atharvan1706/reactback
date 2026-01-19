// backend/models/Dashboard.js - FIXED VERSION WITH COMPLETE FIELD PERSISTENCE
import mongoose from 'mongoose';

const PanelSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { type: String, required: false }, // Made optional since frontend doesn't always send it
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
  
  // ✅ CRITICAL FIELDS THAT WERE MISSING
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
  
  // Fix panels missing 'type' field by using 'vizType' or defaulting to 'chart'
  if (this.panels && Array.isArray(this.panels)) {
    this.panels.forEach(panel => {
      if (panel && !panel.type && panel.vizType) {
        panel.type = 'chart'; // Default type for visualization panels
        console.log(`✅ Auto-assigned type='chart' to panel: ${panel.id}`);
      }
      
      // ✅ Ensure critical fields have defaults if missing
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
    });
    
    // Now filter out any panels that are still invalid
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
