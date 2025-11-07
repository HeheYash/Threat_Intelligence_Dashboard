// MongoDB initialization script for CTI Dashboard
// This script creates the initial database structure and indexes

// Switch to the CTI database
db = db.getSiblingDB('ctidb');

// Create collections if they don't exist
print('Creating collections...');

// IOCs collection with indexes
db.createCollection('iocs');
print('Created iocs collection');

// Create indexes for IOCs collection
db.iocs.createIndex({ "ioc_type": 1, "value": 1 }, { unique: true });
print('Created unique index on ioc_type and value');

db.iocs.createIndex({ "value": 1 });
print('Created index on value');

db.iocs.createIndex({ "threat_score": -1 });
print('Created index on threat_score (descending)');

db.iocs.createIndex({ "last_seen": -1 });
print('Created index on last_seen (descending)');

db.iocs.createIndex({ "created_at": -1 });
print('Created index on created_at (descending)');

db.iocs.createIndex({ "sources": 1 });
print('Created index on sources');

// Feeds metadata collection
db.createCollection('feeds_meta');
print('Created feeds_meta collection');

// Create indexes for feeds_meta collection
db.feeds_meta.createIndex({ "feed_name": 1 }, { unique: true });
print('Created unique index on feed_name');

db.feeds_meta.createIndex({ "last_fetch": -1 });
print('Created index on last_fetch');

// Users collection (for future authentication features)
db.createCollection('users');
print('Created users collection');

// Create indexes for users collection
db.users.createIndex({ "username": 1 }, { unique: true });
print('Created unique index on username');

db.users.createIndex({ "email": 1 }, { unique: true });
print('Created unique index on email');

// Watchlist collection (for future features)
db.createCollection('watchlist');
print('Created watchlist collection');

// Create indexes for watchlist collection
db.watchlist.createIndex({ "ioc_value": 1, "user_id": 1 }, { unique: true });
print('Created unique index on ioc_value and user_id');

db.watchlist.createIndex({ "created_at": -1 });
print('Created index on created_at');

// Audit log collection (for compliance and security)
db.createCollection('audit_log');
print('Created audit_log collection');

// Create indexes for audit_log collection
db.audit_log.createIndex({ "timestamp": -1 });
print('Created index on timestamp');

db.audit_log.createIndex({ "user_id": 1 });
print('Created index on user_id');

db.audit_log.createIndex({ "action": 1 });
print('Created index on action');

// Insert sample configuration data
print('Inserting configuration data...');

// Insert default feeds metadata
db.feeds_meta.insertMany([
  {
    feed_name: "virustotal",
    last_fetch: null,
    total_iocs: 0,
    status: "inactive",
    api_rate_limit_remaining: 4,
    error_message: null,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    feed_name: "abuseipdb",
    last_fetch: null,
    total_iocs: 0,
    status: "inactive",
    api_rate_limit_remaining: 1000,
    error_message: null,
    created_at: new Date(),
    updated_at: new Date()
  },
  {
    feed_name: "openfeeds",
    last_fetch: null,
    total_iocs: 0,
    status: "active",
    api_rate_limit_remaining: null,
    error_message: null,
    created_at: new Date(),
    updated_at: new Date()
  }
]);

print('Inserted default feeds metadata');

// Insert sample admin user (password: admin123 - change immediately!)
db.users.insertOne({
  username: "admin",
  email: "admin@example.com",
  password_hash: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.s5uO8G", // admin123
  role: "admin",
  is_active: true,
  created_at: new Date(),
  last_login: null
});

print('Inserted default admin user');

// Create database view for high-threat IOCs
db.createView("high_threat_iocs", "iocs", [
  {
    $match: {
      threat_score: { $gte: 70 }
    }
  },
  {
    $sort: { threat_score: -1, last_seen: -1 }
  },
  {
    $project: {
      _id: 1,
      value: 1,
      ioc_type: 1,
      threat_score: 1,
      threat_level: 1,
      sources: 1,
      last_seen: 1,
      meta: 1
    }
  }
]);

print('Created high_threat_iocs view');

// Create database view for recent IOCs
db.createView("recent_iocs", "iocs", [
  {
    $match: {
      last_seen: {
        $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Last 7 days
      }
    }
  },
  {
    $sort: { last_seen: -1 }
  },
  {
    $project: {
      _id: 1,
      value: 1,
      ioc_type: 1,
      threat_score: 1,
      threat_level: 1,
      sources: 1,
      last_seen: 1
    }
  }
]);

print('Created recent_iocs view');

// Set up database user for application
print('Creating database user...');

db.createUser({
  user: "cti_app",
  pwd: "cti_app_password",
  roles: [
    {
      role: "readWrite",
      db: "ctidb"
    }
  ]
});

print('Created cti_app user');

// Grant necessary permissions
print('Setting up database permissions...');

// Create role for read-only access (for reporting/analytics)
db.createRole({
  role: "readOnlyAnalytics",
  privileges: [
    {
      resource: { db: "ctidb", collection: "" },
      actions: ["find"]
    }
  ],
  roles: []
});

print('Created readOnlyAnalytics role');

// Insert initial statistics document
db.stats.insertOne({
  _id: "initial_stats",
  total_iocs: 0,
  last_updated: new Date(),
  database_version: "1.0.0"
});

print('Inserted initial statistics');

// Create text index for full-text search on IOC values
db.iocs.createIndex({
  value: "text",
  "meta.tags": "text",
  "sources": "text"
}, {
  weights: {
    value: 10,
    "meta.tags": 5,
    sources: 3
  },
  name: "ioc_text_search"
});

print('Created text search index');

print('MongoDB initialization completed successfully!');
print('');
print('Important security notes:');
print('1. Change default passwords immediately');
print('2. Configure proper authentication for production');
print('3. Set up appropriate network firewall rules');
print('4. Enable MongoDB audit logging for compliance');
print('5. Regularly update MongoDB and application dependencies');
print('');
print('Default credentials:');
print('- Database: cti_app / cti_app_password');
print('- Admin user: admin / admin123 (CHANGE IMMEDIATELY!)');
print('- Root user: cti_admin / cti_secure_password');