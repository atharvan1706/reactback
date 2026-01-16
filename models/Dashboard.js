// backend/models/Dashboard.js - FIXED VERSION
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
