// upload.js
function uploadFile() {
  const formData = new FormData();
  const fileInput = document.getElementById('fileInput');
  var val = '';
  console.log("here is val: ", document.getElementById('isTor').value);
  if(document.getElementById('isTor').value == 'true'){
    val = true;
  }else{
    val = false;
  }
  const isTor = val;
  formData.append("pcapFile", fileInput.files[0]);
  formData.append("isTor", isTor);
  console.log('filepath:', fileInput.files[0]);
  console.log("is tor: ", isTor);
  // Show the loading symbol
  document.getElementById('loader').style.display = 'block';

  fetch('/upload', {
      method: 'POST',
      body: formData,
  })
  .then(response => response.json())
  .then(data => {
      // Hide the loading symbol
      console.log(data.accuracy);
      document.getElementById('loader').style.display = 'none';
      var floatNumber = parseFloat(data.accuracy);
      floatNumber = floatNumber*100;
      // Display the accuracy result
      const accuracyElement = document.getElementById('accuracyResult');
      if (data.accuracy) {
          accuracyElement.innerHTML = `The ML Model returned with <strong> Accuracy: ${floatNumber.toFixed(2)}%</strong>`;
      } else {
          accuracyElement.innerHTML = `An error occurred while processing the file.`;
      }
  })
  .catch(error => {
      console.error('Error:', error);
      // Hide the loading symbol in case of error as well
      document.getElementById('loader').style.display = 'none';
      document.getElementById('accuracyResult').innerHTML = `Failed to fetch the accuracy: ${error}.`;
  });
}
