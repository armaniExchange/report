
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
      ov_new_conn_l7: self.random(),
      ov_new_conn_l4: self.random(),
      ov_new_conn_ssl: self.random(),
      ov_new_conn_ipnat: self.random()
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
      const key = `.rpt.${this.currenttimestamp + i * 2}.category.2015.a5125672-160d-11e7-9ba1-001fa001dd34`;
      console.log(key);
      callback(key, self.record());
      callback(`.test2.${this.currenttimestamp + i * 2}.category.2016.a5125672-160d-11e7-9ba1-001fa001dd34`, self.record());
      callback(`.test3.${this.currenttimestamp + i * 2}.category.2017.a5125672-160d-11e7-9ba1-001fa001dd34`, self.record());
    }
  }

  repeatData(callback) {
    data.map((value, key) => {
      callback(value, key);
    });
  }
}

export default Faker;
