// import levelup from 'levelup';
import config from '../config';
import level from 'level-party';


class KnowLevel {

  constructor(name, type) {
    this.name = name;
    this.type = type || 'report';
  }

  getDB() {
    if (!this.db) {
      const options = {
        valueEncoding: 'json',
        blockSize: 1024 * 1024
      };
      this.db = level(`${config.dbPath}/${this.name}`, options);
    }
    return this.db;
    
  }

  save(key, value) {
    const self = this;
    return new Promise((resolve, reject) => {
      const db = self.getDB();
      db.put(key, value, function(err) {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      })
    });
  }

  analysisRecord(data, filter) {
    const self = this;
    const key = data.key;
    let value = data.value;
    if (typeof(value) === 'string') {
      value = JSON.parse(value);
    }

    if (self.type != 'report') {
      return value;
    }

    // Handle report data.
    const keys = key.split('.');
    if (keys.length === 5) {
      const timestamp = parseInt(keys[3]);
      if (filter && typeof(filter) === 'function') {
        filter(keys[4], value);
      }
      return {timestamp: timestamp, data: value};
    }
  }

  find(options, filter) {
    const self = this;
    return new Promise((resolve, reject) => {
      let records = [];
      const db = self.getDB();
      options = options || {};
      options = Object.assign({ keys: true, values: true }, options);
      db.createReadStream(options)
        .on('data', (data) => {
          if (data) {
            records.push(self.analysisRecord(data, filter));
          }
        })
        .on('end', () => {
          resolve(records);
        });
    });
  }

  findWithKey(options) {
    const self = this;
    return new Promise((resolve, reject) => {
      let records = [];
      const db = self.getDB();
      options = options | {};
      options = Object.assign({ keys: true, values: true }, options);
      db.createReadStream(options)
        .on('data', (data) => {
          if (data) {
            records.push(data);
          }
        })
        .on('end', () => {
          resolve(records);
        });
    });
  }

  batch(options) {
    const self = this;
    console.log(options);
    return new Promise((resolve, reject) => {
      const db = self.getDB();
      db.batch(options, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  close() {
    const db = this.getDB();
    if (db && !db.isClosed()) {
      db.close();
    }
  }

}

export default KnowLevel;
