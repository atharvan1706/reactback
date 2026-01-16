// backend/routes/dashboards.js - WITH SCADA SUPPORT
import express from 'express';
import Dashboard from '../models/Dashboard.js';
import { authMiddleware } from '../middleware/auth.js';

const router = express.Router();

// Get all dashboards for the authenticated user
router.get('/', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const plantId = req.user.plantId || req.user.plantAccess?.[0]?.plantId;

    if (!plantId) {
      return res.status(400).json({
        success: false,
        message: 'No plant ID found for user'
      });
    }

    const dashboards = await Dashboard.find({
      userId,
      plantId
    }).sort({ createdAt: -1 });

    console.log('📊 Fetched dashboards:', dashboards.length);

    res.json({
      success: true,
      dashboards
    });
  } catch (error) {
    console.error('❌ Error fetching dashboards:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboards',
      error: error.message
    });
  }
});

// Get a single dashboard by ID
router.get('/:id', authMiddleware, async (req, res) => {
  try {
    const dashboard = await Dashboard.findOne({
      id: req.params.id,
      userId: req.user.id
    });

    if (!dashboard) {
      return res.status(404).json({
        success: false,
        message: 'Dashboard not found'
      });
    }

    res.json({
      success: true,
      dashboard
    });
  } catch (error) {
    console.error('❌ Error fetching dashboard:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch dashboard',
      error: error.message
    });
  }
});

// Create a new dashboard
router.post('/', authMiddleware, async (req, res) => {
  try {
    const { name, plantId, panels = [], isDefault = false } = req.body;
    const userId = req.user.id;

    if (!name || !plantId) {
      return res.status(400).json({
        success: false,
        message: 'Name and plantId are required'
      });
    }

    // Generate unique ID
    const id = `dashboard_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // ✅ Process panels to ensure SCADA data is saved
    const processedPanels = panels.map(panel => ({
      ...panel,
      // Ensure SCADA fields are included if they exist
      scadaElements: panel.scadaElements || [],
      scadaConnections: panel.scadaConnections || [],
      scadaConfig: panel.scadaConfig || {}
    }));

    const dashboard = new Dashboard({
      id,
      name,
      userId,
      plantId,
      panels: processedPanels,
      isDefault
    });

    await dashboard.save();

    console.log('✅ Dashboard created:', {
      id: dashboard.id,
      name: dashboard.name,
      panelsCount: dashboard.panels.length,
      scadaPanels: dashboard.panels.filter(p => p.type === 'scada').length
    });

    res.status(201).json({
      success: true,
      dashboard
    });
  } catch (error) {
    console.error('❌ Error creating dashboard:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create dashboard',
      error: error.message
    });
  }
});

// Update a dashboard
router.put('/:id', authMiddleware, async (req, res) => {
  try {
    const { name, panels, isDefault } = req.body;

    const dashboard = await Dashboard.findOne({
      id: req.params.id,
      userId: req.user.id
    });

    if (!dashboard) {
      return res.status(404).json({
        success: false,
        message: 'Dashboard not found'
      });
    }

    // Update fields if provided
    if (name !== undefined) dashboard.name = name;
    if (isDefault !== undefined) dashboard.isDefault = isDefault;
    
    if (panels !== undefined) {
      // ✅ Process panels to ensure SCADA data is preserved
      dashboard.panels = panels.map(panel => ({
        ...panel,
        // Preserve SCADA fields
        scadaElements: panel.scadaElements || [],
        scadaConnections: panel.scadaConnections || [],
        scadaConfig: panel.scadaConfig || {}
      }));
    }

    await dashboard.save();

    console.log('✅ Dashboard updated:', {
      id: dashboard.id,
      panelsCount: dashboard.panels.length,
      scadaPanels: dashboard.panels.filter(p => p.type === 'scada').length,
      totalScadaElements: dashboard.panels
        .filter(p => p.type === 'scada')
        .reduce((sum, p) => sum + (p.scadaElements?.length || 0), 0)
    });

    res.json({
      success: true,
      dashboard
    });
  } catch (error) {
    console.error('❌ Error updating dashboard:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update dashboard',
      error: error.message
    });
  }
});

// Update only panels (PATCH endpoint for panel updates)
router.patch('/:id/panels', authMiddleware, async (req, res) => {
  try {
    const { panels } = req.body;

    if (!panels || !Array.isArray(panels)) {
      return res.status(400).json({
        success: false,
        message: 'Panels array is required'
      });
    }

    const dashboard = await Dashboard.findOne({
      id: req.params.id,
      userId: req.user.id
    });

    if (!dashboard) {
      return res.status(404).json({
        success: false,
        message: 'Dashboard not found'
      });
    }

    // ✅ Update panels with SCADA data preservation
    dashboard.panels = panels.map(panel => ({
      ...panel,
      // Ensure SCADA data is included
      scadaElements: panel.scadaElements || [],
      scadaConnections: panel.scadaConnections || [],
      scadaConfig: panel.scadaConfig || {}
    }));

    await dashboard.save();

    console.log('✅ Panels updated:', {
      dashboardId: dashboard.id,
      panelsCount: dashboard.panels.length,
      scadaPanels: dashboard.panels.filter(p => p.type === 'scada').length,
      scadaDetails: dashboard.panels
        .filter(p => p.type === 'scada')
        .map(p => ({
          panelId: p.id,
          title: p.title,
          elements: p.scadaElements?.length || 0,
          connections: p.scadaConnections?.length || 0
        }))
    });

    res.json({
      success: true,
      dashboard
    });
  } catch (error) {
    console.error('❌ Error updating panels:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update panels',
      error: error.message
    });
  }
});

// Delete a dashboard
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const result = await Dashboard.findOneAndDelete({
      id: req.params.id,
      userId: req.user.id
    });

    if (!result) {
      return res.status(404).json({
        success: false,
        message: 'Dashboard not found'
      });
    }

    console.log('✅ Dashboard deleted:', req.params.id);

    res.json({
      success: true,
      message: 'Dashboard deleted successfully'
    });
  } catch (error) {
    console.error('❌ Error deleting dashboard:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete dashboard',
      error: error.message
    });
  }
});

// ✅ Debug endpoint to inspect SCADA data
router.get('/:id/scada-debug', authMiddleware, async (req, res) => {
  try {
    const dashboard = await Dashboard.findOne({
      id: req.params.id,
      userId: req.user.id
    });

    if (!dashboard) {
      return res.status(404).json({
        success: false,
        message: 'Dashboard not found'
      });
    }

    const scadaPanels = dashboard.panels.filter(p => p.type === 'scada');
    const debugInfo = {
      dashboardId: dashboard.id,
      dashboardName: dashboard.name,
      totalPanels: dashboard.panels.length,
      scadaPanelsCount: scadaPanels.length,
      scadaPanels: scadaPanels.map(panel => ({
        panelId: panel.id,
        title: panel.title,
        hasScadaElements: !!panel.scadaElements,
        elementsCount: panel.scadaElements?.length || 0,
        hasScadaConnections: !!panel.scadaConnections,
        connectionsCount: panel.scadaConnections?.length || 0,
        hasScadaConfig: !!panel.scadaConfig,
        sampleElement: panel.scadaElements?.[0] || null,
        sampleConnection: panel.scadaConnections?.[0] || null
      }))
    };

    res.json({
      success: true,
      debug: debugInfo
    });
  } catch (error) {
    console.error('❌ Error in SCADA debug:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get debug info',
      error: error.message
    });
  }
});

export default router;
