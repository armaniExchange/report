
import express from 'express';

import KnowLevel from './src/knowLevel';
import ReportApi from './src/reportApi';


const app = express();

const reportApi = new ReportApi()

app.get('/report', function(req, res) {

  // const category = req.query.category;
  // const startime = req.query['start-time'];
  // const endtime = req.query['end-time'];
  console.log('Request Params:', req.query);

  reportApi.find(req.query, function(records) {
    res.send(records);
  });
  
});

app.get('/', function(req, res) {
  res.sendfile('index.html');
});

app.listen(3000, function() {
  console.log('Example app listening on port 3000');
});
