const http = require('http');
const fs   = require('fs').promises;
const path = require('path'); 

const PORT = 8080;

const MDS_DATA = path.join(__dirname, 'convenience-metadata.json')

const server = http.createServer(async (req,res) => {

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Origin', 'OPTIONS, POST');

    try{
        const data = await fs.readFile(MDS_DATA);

        res.writeHead(200, {
            'content-Type': 'application/octet-stream', 
            'Content-Disposition': 'attachment; filename="convenience-metadata.json"' 
        });
        res.end(data)
        
    }
    catch (err) {
                
        res.writeHead(404, {'content-type': 'text/plain'});
        res.end('File not found');
            
    }

});

server.listen(PORT, 'localhost', () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});