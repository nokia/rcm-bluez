'use strict';

let ledCharacteristic = [];
let turnedOn = false;
let colorWheel = null;
let oldColor = null;
let mouseIsDown = false;

colorWheel = iro.ColorWheel("#color-wheel", {
	width: 320,
	height: 320,
	padding: 4,
	sliderMargin: 24,
	markerRadius: 8,
	color: "rgb(255, 255, 255)",
	styles: {
		".on-off": {
			"background-color": "rgb"
		},
		".on-off:hover": {
			"background-color": "rgb"
		}
	}
});

document.querySelector('.wheel').addEventListener('mousedown', function (e) {
	handleMouseDown(e);
}, false);
document.querySelector('.wheel').addEventListener('mousemove', function (e) {
	handleMouseMove(e);
}, false);
document.querySelector('.wheel').addEventListener('mouseup', function (e) {
	handleMouseUp(e);
}, false);

function handleMouseDown(e) {

	// mousedown stuff here
	mouseIsDown = true;
}

function handleMouseUp(e) {
	updateColor();

	// mouseup stuff here
	mouseIsDown = false;
}

function handleMouseMove(e) {
	if (!mouseIsDown) {
		return;
	}

	updateColor();
}

function updateColor() {
	if (oldColor != null && oldColor != "" && oldColor != colorWheel.color.rgbString) {
		setColor(colorWheel.color.rgb.r, colorWheel.color.rgb.g, colorWheel.color.rgb.b);
	}

	oldColor = colorWheel.color.rgbString;
}

function onConnected() {
	document.querySelector('.connect-button').classList.add('hidden');
	document.querySelector('.connect-another').classList.remove('hidden');
	document.querySelector('.wheel').classList.remove('hidden');
	document.querySelector('.mic-button').classList.remove('hidden');
	document.querySelector('.power-button').classList.remove('hidden');
	turnedOn = false;
}

function connect() {


//	filters: [
// 	{name: 'BeeWi SmartLite'}] ,
// 	optionalServices: ['a8b3fff0-4834-4051-89d0-3de95cddd318'],
//	acceptAllDevices: true		
//		})
let options = {
//	filters: [{ services: ['a8b3fff0-4834-4051-89d0-3de95cddd318'] }],
	optionalServices: ['a8b3fff0-4834-4051-89d0-3de95cddd318'],
	acceptAllDevices: true
}

	console.log('Requesting Bluetooth Device...');
	navigator.bluetooth.requestDevice(options)
		.then(device => {
			console.log('> Found ' + device.name);
			console.log('Connecting to GATT Server...');
			return device.gatt.connect();
		})
		.then(server => {
			console.log('Getting Service 0xffe5 - Light control...');
			return server.getPrimaryService('a8b3fff0-4834-4051-89d0-3de95cddd318'); })
		.then(service => {
		return service.getCharacteristic('a8b3fff1-4834-4051-89d0-3de95cddd318'); })
		.then(characteristic => {

			if (!ledCharacteristic.includes(characteristic)) {
				ledCharacteristic.push(characteristic);
				if (ledCharacteristic.length > 1) document.querySelector('#title').innerHTML += " x" + ledCharacteristic.length;
				console.log('All ready! ' + characteristic.service.device.name + " added");
			}
			onConnected();
		})
		.catch(error => {
			console.log('Argh! ' + error);
		});
}

function turnOn() {
// turn led off; 

	let data = new Uint8Array([0x55, 0x10, 0x00, 0x0d, 0x0a]); 
	return ledCharacteristic.forEach(led => led.writeValue(data)
		.catch(err => console.log('Error when turning on! ', err))
		.then(() => {
			turnedOn = true;
			toggleButtons();
		}));
}

function turnOff() {
	let data = new Uint8Array([0x55, 0x10, 0x01, 0x0d, 0x0a]); 
	return ledCharacteristic.forEach(led => led.writeValue(data)
		.catch(err => console.log('Error when turning off! ', err))
		.then(() => {
			turnedOn = false;
			toggleButtons();
		}));
}

function turnOnOff() {
	if (turnedOn) {
		turnOff();
	} else {
		turnOn();
	}
}

function toggleButtons() {
	Array.from(document.querySelectorAll('.color-buttons button')).forEach(function (colorButton) {
		colorButton.disabled = !turnedOn;
	});
	document.querySelector('.mic-button button').disabled = !turnedOn;
    turnedOn ? document.querySelector('.wheel').classList.remove('hidden') : document.querySelector('.wheel').classList.add('hidden');
}

function setColor(red, green, blue) {
let data = new Uint8Array([0x55, 0x13, red, green, blue, 0x0d, 0x0a]); 
// turn led on; [0x55, 0x10, 0x01, 0x0d, 0x0a]
 // color change patterns; [0x55, 0x17, pat, 0x0d, 0x0a] 
	return ledCharacteristic.forEach(led => led.writeValue(data)
		.catch(err => console.log('Error when writing value! ', err)));
}

function red() {
	return setColor(255, 0, 0)
		.then(() => console.log('Color set to Red'));
}

function green() {
	return setColor(0, 255, 0)
		.then(() => console.log('Color set to Green'));
}

function blue() {
	return setColor(0, 0, 255)
		.then(() => console.log('Color set to Blue'));
}

function listen() {
	annyang.start({
		continuous: true
	});
}

// Voice commands
// annyang.addCommands({
// 	'red': red,
// 	'green': green,
// 	'blue': blue,
// 	'turn on': turnOn,
// 	'turn off': turnOff
// });

// Install service worker - for offline support
// if ('serviceWorker' in navigator) {
// 	navigator.serviceWorker.register('serviceworker.js');
// }
