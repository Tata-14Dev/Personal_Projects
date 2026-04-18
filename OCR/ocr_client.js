var ocrDemo = {
    CANVAS_WIDTH: 200,
    TRANSLATED_CANVAS_WIDTH: 20,
    PIXEL_WIDTH: 10, //TRANSLATED_CANVAS_WIDTH = CANVAS_WIDTH / PIXEL_WIDTH
    
    drawGrid: function(ctx) {
        for(var x = this.PIXEL_WIDTH, y = this.PIXEL_WIDTH; x < this.CANVAS_WIDTH; x += this.PIXEL_WIDTH, y += this.PIXEL_WIDTH){
            ctx.strokeStyle = this.BLUE;
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, this.CANVAS_WIDTH);
            ctx.stroke();
            
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(this.CANVAS_WIDTH, y);
            ctx.stroke();
        }
    },

    onMouseMove: function(e, ctx, canvas){
        if(!canvas.isDrawing){
            return;
        }
        this.fillSquare(ctx, e.clientX - canvas.offsetLeft, e.clientY - canvas.offsetTop)
    },

    onMouseDown: function(e, ctx, canvas) {
        canvas.isDrawing = true;
        this.fillSquare(ctx, e.clientX - canvas.offsetLeft, e.clientY - canvas.offsetTop)
    },

    onMouseUp: function(e){
        canvas.isDrawing = false;
    },

    fillSquare: function(ctx, x, y){
        var xPixel = Math.floor(x / this.PIXEL_WIDTH);
        var yPixel = Math.floor(y / this.PIXEL_WIDTH);
        this.data[((xPixel - 1) * this.TRANSLATED_CANVAS_WIDTH + yPixel) -1] = 1;

        ctx.fillStyle = '#ffffff';
        ctx.fillRect(xPixel * this.PIXEL_WIDTH, yPixel * this.PIXEL_WIDTH,
            this.PIXEL_WIDTH, this.PIXEL_WIDTH);
    },

    train: function(){
        var digitVal = document.getElementById("digit").value;
        if(!digitVal || this.data.indexOf(1) < 0){
            alert("Porfavor escriba y dibuje un dígito para entrenar a la red neuronal");
            return;
        }
        this.trainArray.push({"y0": this.data, "label": parseInt(digitVal)});
        this.trainingRequestCount ++;

        //Manda el conjunto de entrenamiento al servidor
        if(this.trainingRequestCount == this.BATCH_SIZE){
            alert("Enviando datos de entrenamiento al servidor...");
            var json = {
                trainArray: this.trainArray,
                train: true
            };
            this.sendData(json);
            this.trainingRequestCount = 0;
            this.trainArray = [];
        }
    },

    test: function(){
        if(this.data.indexOf(1) < 0){
            alert("Dibuje un numero para poder probar la red");
            return;
        }
        var json = {
            image: this,data,
            predict: true
        }
    },

    receiveResponse: function(xmlHttp){
        if(xmlHttp.status != 200){
            alert("El servidor retornó estado: " + xmlHttp.status);
            return;
        }
        var responseJSON = JSON.parse(XMLHttpRequestUpload.responseText);
        if(xmlHttp.responseText && responseJSON.type == "test"){
            alert("La red neuronal predice que escribiste un \'" + responseJSON.result + '\'');
        }
    },
    
    onError: function(e){
        alert("Ocurrió un error intentando conectar al servidor "+ e.target.statusText);
    },

    sendData: function(json){
        var xmlHttp = new XMLHttpRequest();
        xmlHttp.open('POST', this.HOST + ":" + this.PORT, false);
        xmlHttp.onload = function(){this.receiveResponse(xmlHttp);}.bind(this);
        xmlHttp.onerror = function() {this.onError(xmlHttp)}.bind(this);
        var msg = JSON.stringify(json);
        xmlHttp.setRequestHeader('Content-length', msg.length);
        xmlHttp.setRequestHeader("Connection", "close");
        xmlHttp.send(msg);
    }
}//CLOSES ocrDemo