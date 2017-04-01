
import data from './data.json';

class Faker {

  constructor() {
    this.currenttimestamp = new Date().getTime(); 
    console.log(this.currenttimestamp);
  }

  random() {
    return Math.round(Math.random() * 1000)
  }

  record() {
    const self = this;
    return {
      1: self.random(),
      2: self.random(),
      3: self.random(),
      4: self.random(),
      5: self.random(),
      6: self.random(),
      7: self.random(),
      8: self.random()
    };
  }

  repeat(times, callback) {
    if (!(callback && typeof(callback) === 'function')) {
      return ;
    }

    // category
    // timestamp
    const self = this;
    for (let i = 0; i < times; i++) {
      const key = `.test1.${this.currenttimestamp + i * 2}.category.2015.a5125672-160d-11e7-9ba1-001fa001dd34`;
      console.log(key);
      callback(key, self.record());
      callback(`.test2.${this.currenttimestamp + i * 2}.category.2016.a5125672-160d-11e7-9ba1-001fa001dd34`, self.record());
      callback(`.test3.${this.currenttimestamp + i * 2}.category.2017.a5125672-160d-11e7-9ba1-001fa001dd34`, self.record());
    }

    // for (let i = 0; i < times; i++) {
    //   const key = `.time.category.2015.a5125672-160d-11e7-9ba1-001fa001dd35.${this.currenttimestamp + i}`;
    //   console.log(key);
    //   callback(key, self.record());
    // }
    // for (let i = 0; i < times; i++) {
    //   const key = `.time.category.2016.a5125672-160d-11e7-9ba1-001fa001dd36.${this.currenttimestamp + i}`;
    //   console.log(key);
    //   callback(key, self.record());
    // }
  }

  repeatData(callback) {
    data.map((value, key) => {
      // callback(key, value);
      callback(value, key);
    });
  }
}

export default Faker;
