// backend/models/Dashboard.js - FIXED VERSION
import mongoose from 'mongoose';

const PanelSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { type: String, required: true },
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

// Filter invalid panels BEFORE validation runs
DashboardSchema.pre('validate', function() {
  this.updatedAt = new Date();
  
  // Filter out panels that are missing required fields
  if (this.panels && Array.isArray(this.panels)) {
    const originalLength = this.panels.length;
    this.panels = this.panels.filter(panel => {
      const isValid = panel && panel.id && panel.type && panel.title;
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
