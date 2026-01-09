// backend/models/Dashboard.js
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

// Update the updatedAt timestamp before saving
DashboardSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Compound index for user and plant queries
DashboardSchema.index({ userId: 1, plantId: 1 });

const Dashboard = mongoose.model('Dashboard', DashboardSchema);

export default Dashboard;
