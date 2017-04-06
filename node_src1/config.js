const config = {
  dbPath: 'D:/dev/Project/use-level/db',
  objDB: 'obj_db',
  rawDB: 'raw_db',
  reducedDB: {
    '30m': {
      fromDB: 'basic',
      name: 'record-30m',
      duration: 18,
    },
    '1h': {
      fromDB: '30m',
      name: 'record-1h',
      duration: 36
    },
    '7h': {
      fromDB: '1h',
      name: 'record-7h',
      duration: 36 * 7
    },
    '1d': {
      fromDB: '1h',
      name: 'record-1d',
      duration: 36 * 24
    },
    '7d': {
      fromDB: '1d',
      name: 'record-7d',
      duration: 36 * 24 * 7
    },
    '30d': {
      fromDB: '1d',
      name: 'record-30d',
      duration: 36 * 24 * 30
    }
  }
};

export default config;