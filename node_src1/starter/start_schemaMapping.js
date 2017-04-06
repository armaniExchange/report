
import SchemaMapping from '../src/schemaMapping';

const mapping = new SchemaMapping();

mapping.get(398).then((result) => {
  console.log(result);
});

