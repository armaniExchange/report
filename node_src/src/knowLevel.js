// import levelup from 'levelup';
import config from '../config';
import level from 'level-party';


class KnowLevel {

  constructor(name) {
    this.name = name;
  }

  getDB() {
    const options = {
      valueEncoding: 'json'
    };
    return level(config.dbPath + `/${this.name}`, options);
  }

  saveRecord(key, value, callback) {
    try {
      var db = this.getDB();
      db.put(key, value, function(err) {
        db.close();
        if (err){
          // some kind of I/O error
          return console.log('Ooops!', err) 
        };
        if (callback && typeof(callback) === 'function') {
          callback();
        }
      })
    } catch (e) {
      console.log(e);
    }
  }

  findRecord(key, callback) {
    try {
      var db = this.getDB();
      db.get(key, function (err, value) {
        db.close();
        if (err) {
          // likely the key was not found
          return console.log('Ooops!', err);
        }
        if (callback && typeof(callback) === 'function') {
          callback(value);
        }
      });
    } catch(e) {
      console.log(e);
    }
  }

  find(options, callback, filter) {
    try {
      var records = [];
      var db = this.getDB();
      db.createReadStream(options)
        .on('data', (data) => {
          const key = data.key;
          const keys = key.split('.');
          if (keys.length === 5) {
            const timestamp = parseInt(keys[3]);
            const value = JSON.parse(data.value);
            if (filter && typeof(filter) === 'function') {
              filter(keys[4], value);
            }

            records.push({
              timestamp: timestamp,
              data: value
            });
          }
          
        })
        .on('end', () => {
          db.close();
          if (callback && typeof(callback) === 'function') {
            callback(records);
          }
        });
      
    } catch(e) {
      console.log(e);
    }
  }

  batch(options, callback) {
    const db = this.getDB();
    db.batch(options, (err) => {
      if (err) {
        console.log('Ooops!', err)
      }
    });
  }
}

export default KnowLevel;
