function uploadFile() {
  const formData = new FormData();
  const fileInput = document.getElementById('fileInput');
  formData.append("pcapFile", fileInput.files[0]);
  document.getElementById('loader').style.display = 'block';

  fetch('/upload', {
      method: 'POST',
      body: formData,
  })
  .then(response => response.json())
  .then(data => {
      document.getElementById('loader').style.display = 'none';
      const resultElement = document.getElementById('result');
      if (data.torIPs) {
          let content = '<h3>Tor IPs Detected:</h3>';
          data.torIPs.forEach(ip => {
              content += `<p>IP: ${ip.Src_IP} &rarr; ${ip.Dst_IP} | Confidence: ${(ip.Confidence*100).toFixed(2)}%</p>`;
          });
          resultElement.innerHTML = content;
      } else {
          resultElement.innerHTML = 'No Tor IPs detected or an error occurred.';
      }
  })
  .catch(error => {
      console.error('Error:', error);
      document.getElementById('loader').style.display = 'none';
      document.getElementById('result').innerHTML = `Failed to process the file: ${error}.`;
  });
}
