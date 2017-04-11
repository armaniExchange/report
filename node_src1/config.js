const config = {
  dbPath: 'D:/dev/Project/use-level/db',
  objDB: 'obj_db',
  rawDB: 'raw_db',
  duration: 15 * 24 * 3600,
  reducedDB: {
    '30m': {
      fromDB: 'basic',
      name: 'record-30m',
      interval: 18,
      duration: 15 * 24 * 3600
    },
    '1h': {
      fromDB: 'basic',
      name: 'record-1h',
      interval: 36,
      duration: 15 * 24 * 3600
    },
    '7h': {
      fromDB: '1h',
      name: 'record-7h',
      interval: 36 * 7,
      duration: 15 * 24 * 3600
    },
    '1d': {
      fromDB: '1h',
      name: 'record-1d',
      interval: 36 * 24,
      duration: 15 * 24 * 3600
    },
    '7d': {
      fromDB: '1d',
      name: 'record-7d',
      interval: 36 * 24 * 7,
      duration: 30 * 24 * 3600
    },
    '30d': {
      fromDB: '1d',
      name: 'record-30d',
      interval: 36 * 24 * 30,
      duration: 90 * 24 * 3600
    }
  }
};

export default config;