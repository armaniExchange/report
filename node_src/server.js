
import express from 'express';

import KnowLevel from './knowLevel';
import Report from './report';
import Faker from './faker';


const app = express();

const report = new Report()

app.get('/report', function(req, res) {

  const category = req.query.category;
  const startime = req.query['start-time'];
  const endtime = req.query['end-time'];
  console.log('Request Params:', category, startime, endtime);

  report.find(category, startime, endtime, function(records) {
    res.send(records);
  });
  
});

app.get('/', function(req, res) {
  res.sendfile('index.html');
});

app.listen(3000, function() {
  console.log('Example app listening on port 3000');
});
