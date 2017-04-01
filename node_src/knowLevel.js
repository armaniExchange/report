import levelup from 'levelup';


class KnowLevel {

  constructor(levelName) {
    this.levelName = levelName;
  }

  getDB() {
    return levelup(__dirname + `/${this.levelName}`);
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

  find(options, callback) {
    try {
      var records = [];
      var db = this.getDB();
      db.createReadStream(options)
        .on('data', (data) => {
          const key = data.key;
          records.push({
            timestamps: parseInt(key.substring(key.lastIndexOf('.') + 1)),
            data: JSON.parse(data.value)
          });
          // records.push(JSON.parse(data.value));
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
}

export default KnowLevel;
