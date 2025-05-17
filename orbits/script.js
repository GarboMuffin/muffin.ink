// Gravitational constant
const G = 6.674e-11;

const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

const randomColor = () => `hsl(${Math.random() * 360}deg, ${Math.random() * 50 + 50}%, 50%)`;

const MAX_TRAILS = 150; // frames

class Vector {
  constructor(x=0, y=0) {
    this.x = x;
    this.y = y;
  }

  /**
   * @param {Vector} otherVector
   * @returns {number} distance in meters
   */
  distanceTo(otherVector) {
    return Math.sqrt((this.x - otherVector.x) ** 2 + (this.y - otherVector.y) ** 2);
  }

  magnitude() {
    return Math.sqrt(this.x ** 2 + this.y ** 2);
  }

  clone() {
    return new Vector(this.x, this.y);
  }
}

class Rectangle {
  constructor(left, top, right, bottom) {
    /** @type {number} x coordinate of top left corner */
    this.left = left;
    /** @type {number} y coordinate of top left corner */
    this.top = top;
    /** @type {number} x coordinate of bottom right corner */
    this.right = right;
    /** @type {number} y coordinate of bottom right corner */
    this.bottom = bottom;
  }

  get width() {
    return this.right - this.left;
  }

  get height() {
    return this.bottom - this.top;
  }

  /** @param {Rectangle} other */
  intersects(other) {
    return (
      this.left <= other.right &&
      other.left <= this.right &&
      this.top <= other.bottom &&
      other.top <= this.bottom
    );
  }
}

class Energy {
  constructor() {
    /** @type {number} Kinetic energy in joules */
    this.kinetic = 0;

    /** @type {number} Gravitational potential energy in joules */
    this.gravitational = 0;
  }

  /** @returns {number} Total energy in joules */
  total() {
    return this.kinetic + this.gravitational;
  }
}

class TrailLocation {
  constructor(x, y, timestamp) {
    this.x = x;
    this.y = y;
    this.timestamp = timestamp;
  }
}

class Trail {
  constructor() {
    /** @type {TrailLocation[]} */
    this.points = [];
  }

  add(point) {
    this.points.push(point);
    if (this.points.length > MAX_TRAILS) {
      this.points.shift();
    }
  }
}

class PointMass {
  constructor () {
    /** @type {number} mass in kilograms */
    this.mass = 1;

    /** @type {Vector} position in meters */
    this.position = new Vector();

    /** @type {Vector} velocity in meters/second */
    this.velocity = new Vector();

    /** @type {Vector} Net force in Newtons */
    this.netForce = new Vector();

    /** @type {number} radius in meters */
    this.radius = 10;

    /** @type {color} color of the point */
    this.color = 'white';

    /** @type {Trail} Previous positions of the point */
    this.trail = new Trail();

    /** @type {boolean} true if the object is "locked" and can not be moved */
    this.locked = false;

    /** @type {string} User-facing name of object. */
    this.name = 'Object';

    /** @type {boolean} true if the object should not be user-interactable */
    this.uninteractable = false;
  }

  setMass(mass) {
    this.mass = mass;
    return this;
  }

  setRadius(radius) {
    this.radius = radius;
    return this;
  }

  setPosition(x, y) {
    this.position.x = x;
    this.position.y = y;
    return this;
  }

  moveBy(x, y) {
    return this.setPosition(this.position.x + x, this.position.y + y);
  }

  setVelocity(x, y) {
    this.velocity.x = x;
    this.velocity.y = y;
    return this;
  }

  setColor(color) {
    this.color = color;
    return this;
  }

  setName(name) {
    this.name = name;
    return this;
  }

  setUninteractable(uninteractable) {
    this.uninteractable = uninteractable;
    return this;
  }

  clone() {
    return new PointMass()
      .setMass(this.mass)
      .setRadius(this.radius)
      .setPosition(this.position.x, this.position.y)
      .setVelocity(this.velocity.x, this.velocity.y)
      .setColor(this.color)
      .setName(this.name)
      .setUninteractable(this.uninteractable);
  }

  /** @param {number} timeStep How much time has passed, in seconds */
  updateKinematics(timeStep) {
    // Repeated addition of many small time slices approximates an integral

    // Acceleration = Force / Mass
    const accelerationX = this.netForce.x / this.mass;
    const accelerationY = this.netForce.y / this.mass;

    // Integrate acceleration to find velocity
    this.velocity.x += accelerationX * timeStep;
    this.velocity.y += accelerationY * timeStep;

    // Integrate velocity to find position
    this.position.x += this.velocity.x * timeStep;
    this.position.y += this.velocity.y * timeStep;
  }

  /** @param {Simulation} simulation */
  getEnergy (simulation) {
    const energy = new Energy();

    // Kt = 1/2 * m * v^2
    energy.kinetic = 0.5 * this.mass * this.velocity.magnitude() ** 2;

    for (const object of simulation.objects) {
      if (object === this) continue;

      const distance = this.position.distanceTo(object.position);
      // Avoid division by zero. Breaks math.
      if (distance === 0) continue;

      // Ug = -G * m1 * m2 / r
      energy.gravitational += G * this.mass * object.mass / distance;
    }

    return energy;
  }

  getMomentum () {
    // p = m * v
    return this.mass * this.velocity.magnitude();
  }

  getBounds () {
    return new Rectangle(
      this.position.x - this.radius,
      this.position.y - this.radius,
      this.position.x + this.radius,
      this.position.y + this.radius
    );
  }
}

class Fling {
  constructor () {
    this.history = [];
    this.period = 0.075;
  }

  now() {
    return performance.now();
  }

  minimumTimeThreshold() {
    return this.now() - (this.period * 1000);
  }

  update(movementX, movementY) {
    this.history.push({
      x: movementX,
      y: movementY,
      time: this.now()
    });
  }

  calculateVelocity(zoom) {
    const now = this.now();
    const minimumTime = this.minimumTimeThreshold();
    const relevantHistory = this.history.filter(i => i.time >= minimumTime);

    if (relevantHistory.length === 0) {
      return new Vector(0, 0);
    }

    let sumX = 0;
    let sumY = 0;
    for (const {x, y} of relevantHistory) {
      sumX += x;
      sumY += y;
    }

    const oldestTime = relevantHistory[0].time;
    const realPeriod = (now - oldestTime);

    const averageScreenX = (sumX / realPeriod) || 0;
    const averageScreenY = (sumY / realPeriod) || 0;

    const simulationXPerSecond = averageScreenX / zoom;
    const simulationYPerSecond = averageScreenY / zoom;

    return new Vector(simulationXPerSecond, simulationYPerSecond);
  }
}

const statusMessages = document.createElement('div');
statusMessages.style.display = 'flex';
statusMessages.style.alignItems = 'center';
statusMessages.style.justifyContent = 'center';
statusMessages.style.flexDirection = 'column';
statusMessages.style.position = 'absolute';
statusMessages.style.top = '20px';
statusMessages.style.left = '0';
statusMessages.style.width = '100%';
statusMessages.style.zIndex = '100';
statusMessages.style.pointerEvents = 'none';
document.body.appendChild(statusMessages);

class StatusMessage {
  constructor(text) {
    this.el = document.createElement('div')
    this.el.textContent = text;
    this.el.style.background = 'rgba(0, 0, 0, 0.8)';
    this.el.style.border = '1px solid rgba(255, 255, 255, 0.5)';
    this.el.style.color = 'white';
    this.el.style.padding = '8px';
    this.el.style.marginBottom = '8px';
    this.el.style.borderRadius = '8px';
    this.el.style.transition = '.2s';
  }

  flash() {
    statusMessages.prepend(this.el);
    getComputedStyle(this.el).opacity;
    setTimeout(() => {
      this.el.style.opacity = '0';
      setTimeout(() => {
        this.el.remove();
      }, 200);
    }, 500);
  }
}

class Simulation {
  constructor() {
    /** @type {HTMLCanvasElement} */
    this.canvas = document.getElementById('canvas');
    /** @type {CanvasRenderingContext2D} */
    this.ctx = this.canvas.getContext('2d');

    this.updateRollover = 0;

    this.dirty = false;

    this.running = true;

    this.updatesPerSecond = 60;
    /** @param {number} In seconds */
    this.timeStep = 1 / this.updatesPerSecond;

    this.showTrails = false;
    this.markAsDirtyWhenPropertyChanges('showTrails');
    this.showVelocity = false;
    this.markAsDirtyWhenPropertyChanges('showVelocity');
    this.showAcceleration = false;
    this.markAsDirtyWhenPropertyChanges('showAcceleration');

    window.addEventListener('resize', () => {
      this.updateCanvasSize();
    });
    this.updateCanvasSize();

    this.center = new Vector();
    this.zoom = 0.000006339726086728971;

    this.interacting = false;
    /** @type {PointMass|null} */
    this.interactingObject = null;

    this.canvas.addEventListener('mousedown', (e) => {
      e.preventDefault();
      document.activeElement.blur();

      const objectAtPoint = this.getObjectAtScreenPoint(e.clientX, e.clientY);
      if (objectAtPoint && objectAtPoint.uninteractable) {
        return;
      }
      const fling = new Fling();

      this.interacting = true;
      this.interactingObject = objectAtPoint;

      const isMovingObject = !!objectAtPoint;
      const isMovingViewport = !isMovingObject;

      if (isMovingObject) {
        objectAtPoint.locked = true;
        this.dirty = true;
      }

      const mouseup = (e) => {
        e.preventDefault();

        window.removeEventListener('mouseup', mouseup);
        window.removeEventListener('mousemove', mousemove);

        this.interacting = false;

        if (isMovingObject) {
          objectAtPoint.velocity = fling.calculateVelocity(this.zoom);
          objectAtPoint.netForce = new Vector();
          objectAtPoint.locked = false;
          this.dirty = true;
        }
      };

      const mousemove = (e) => {
        e.preventDefault();
        fling.update(e.movementX, e.movementY);
        if (isMovingViewport) {
          this.panBy(e.movementX, e.movementY);
        }
        if (isMovingObject) {
          this.moveObjectBy(objectAtPoint, e.movementX, e.movementY);
        }
      };

      window.addEventListener('mouseup', mouseup);
      window.addEventListener('mousemove', mousemove);
    });

    this.mouseClientX = 0;
    this.mouseClientY = 0;
    this.canvas.addEventListener('mousemove', (e) => {
      this.mouseClientX = e.clientX;
      this.mouseClientY = e.clientY;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      this.zoomBy(e.deltaY, e.clientX, e.clientY);
    });

    this.canvas.addEventListener('contextmenu', (e) => {
      e.preventDefault();
    });

    window.addEventListener('keydown', (e) => {
      const activeObject = this.interactingObject || this.getObjectAtScreenPoint(this.mouseClientX, this.mouseClientY);
      if (activeObject) {
        if (e.key === 'Delete' || e.key === 'Backspace') {
          e.preventDefault();
          this.removeObject(activeObject);
          return;
        }
      }

      let newObject;
      if (e.key === '1') {
        newObject = testObject.clone();
        newObject.setColor(randomColor());
      } else if (e.key === '2') {
        newObject = earth.clone();
      } else if (e.key === '3') {
        newObject = moon.clone();
      } else if (e.key === '4') {
        newObject = smallProjectile.clone();
      }
      if (newObject) {
        newObject.position = this.getSimulationPointAtScreenPoint(this.mouseClientX, this.mouseClientY);
        newObject.setVelocity(0, 0);
        if (this.isSafeToSpawnObject(newObject)) {
          this.addObject(newObject);
        } else {
          new StatusMessage(`${newObject.name} won't fit`).flash();
        }
      }
    });

    /** @type {PointMass[]} */
    this.objects = [];

    this.timestamp = 0;
  }

  markAsDirtyWhenPropertyChanges(property) {
    let actualValue = this[property];
    Object.defineProperty(this, property, {
      get: () => {
        return actualValue;
      },
      set: (newValue) => {
        this.dirty = true;
        actualValue = newValue;
      }
    });
  }

  updateCanvasSize() {
    this.baseWidth = this.canvas.offsetWidth;
    this.baseHeight = this.canvas.offsetHeight;
    this.rect = this.canvas.getBoundingClientRect();
    this.pixelRatio = window.devicePixelRatio;
    this.canvas.width = this.baseWidth * this.pixelRatio;
    this.canvas.height = this.baseHeight * this.pixelRatio;
    this.dirty = true;
  }

  panBy(screenMovementX, screenMovementY) {
    this.center.x -= screenMovementX / this.zoom;
    this.center.y -= screenMovementY / this.zoom;
    this.dirty = true;
  }

  zoomBy(deltaY, screenX, screenY) {
    // When we zoom, we want the point under the mouse cursor to remain the same.
    const point = this.getSimulationPointAtScreenPoint(screenX, screenY);
    const screenDistanceToLeftEdge = screenX - this.rect.left;
    const screenDistanceToTop = screenY - this.rect.top;

    const MIN_ZOOM = 0.000001;
    const MAX_ZOOM = Infinity;
    const ZOOM_SPEED = 0.01;
    const zoomAmount = -deltaY * ZOOM_SPEED;
    this.zoom = clamp(this.zoom * (2 ** zoomAmount), MIN_ZOOM, MAX_ZOOM);

    const newViewport = this.getSimulationViewport();
    const newSimulationLeftEdge = point.x - (screenDistanceToLeftEdge / this.zoom);
    const newSimulationTop = point.y - (screenDistanceToTop / this.zoom);
    this.center.x = newSimulationLeftEdge + (newViewport.width / 2);
    this.center.y = newSimulationTop + (newViewport.height / 2);

    this.dirty = true;
  }

  getSimulationPointAtScreenPoint(clientX, clientY) {
    // These coordinates are all in "screen space"
    const canvasX = clientX - this.rect.left;
    const canvasY = clientY - this.rect.top;
    const fromCenterX = canvasX - (this.baseWidth / 2);
    const fromCenterY = canvasY - (this.baseHeight / 2);
    // Convert to "simulation space"
    return new Vector(
      this.center.x + (fromCenterX / this.zoom),
      this.center.y + (fromCenterY / this.zoom)
    );
  }

  getObjectAtPoint(position) {
    for (const object of this.objects) {
      const distance = object.position.distanceTo(position);
      if (distance < object.radius) {
        return object;
      }
    }
    return null;
  }

  getObjectAtScreenPoint(clientX, clientY) {
    return this.getObjectAtPoint(this.getSimulationPointAtScreenPoint(clientX, clientY));
  }

  isSafeToSpawnObject(newObject) {
    for (const object of this.objects) {
      const distance = object.position.distanceTo(newObject.position);
      if (distance <= object.radius + newObject.radius) {
        return false;
      }
    }
    return true;
  }

  moveObjectBy(object, screenMovementX, screenMovementY) {
    const simulationMovementX = screenMovementX / this.zoom;
    const simulationMovementY = screenMovementY / this.zoom;
    object.position.x += simulationMovementX;
    object.position.y += simulationMovementY;
    this.dirty = true;
  }

  getSimulationViewport() {
    const viewportWidth = this.baseWidth / this.zoom;
    const viewportHeight = this.baseHeight / this.zoom;
    const left = this.center.x - (viewportWidth / 2);
    const top = this.center.y - (viewportHeight / 2);
    return new Rectangle(
      left,
      top,
      left + viewportWidth,
      top + viewportHeight
    );
  }

  calculateZoomIndependentPixels(domPixels) {
    return domPixels / this.zoom;
  }

  reset() {
    this.objects.length = [];
    this.dirty = true;
  }

  addObject(object) {
    if (this.objects.includes(object)) {
      throw new Error('Object already in simulation');
    }
    this.objects.push(object);
    this.dirty = true;
  }

  removeObject(object) {
    this.objects = this.objects.filter(i => i !== object);
    this.dirty = true;
  }

  next(deltaTimeSeconds) {
    if (this.running) {
      // If we calculate that we have to run something like "7.5 steps", we'll carry the 0.5 over to the next
      // step so that if we get another "7.5 steps", we'll do 7 + 8 = 15 steps instead of 7 + 7 = 14 steps.
      const stepsToPerform = deltaTimeSeconds * this.updatesPerSecond + this.updateRollover;
      this.updateRollover = stepsToPerform % 1;
      this.updateCaches();
      for (let i = 0; i < Math.floor(stepsToPerform); i++) {
        this.updateObjects();
      }
    }

    this.updateTrails();

    this.renderCursor();
    this.render();

    // const totalEnergy = new Energy();
    // let totalMomentum = 0;
    // for (const object of this.objects) {
    //   const objectEnergy = object.getEnergy(this);
    //   const objectMomentum = object.getMomentum();
    //   totalMomentum += objectMomentum;
    //   totalEnergy.kinetic += objectEnergy.kinetic;
    //   totalEnergy.gravitational += objectEnergy.gravitational;
    // }
    // console.log(totalEnergy.total(), totalMomentum);
  }

  updateCaches() {
    this.unlockedObjects = this.objects.filter(i => !i.locked);
  }

  updateObjects() {
    this.timestamp += this.timeStep;

    const objects = this.unlockedObjects;

    if (objects.length === 0) {
      // Nothing to do.
      return;
    }

    // Forces are recalculated on every update.
    for (let i = 0; i < objects.length; i++) {
      const object = objects[i];
      object.netForce.x = 0;
      object.netForce.y = 0;
    }

    for (let i = 0; i < objects.length; i++) {
      const objectA = objects[i];
      for (let j = i + 1; j < objects.length; j++) {
        const objectB = objects[j];

        const distance = objectA.position.distanceTo(objectB.position);
        // Avoid division by zero. Breaks math.
        if (distance === 0) continue;

        const deltaX = objectB.position.x - objectA.position.x;
        const deltaY = objectB.position.y - objectA.position.y;

        const nonCollidingDistance = objectA.radius + objectB.radius;
        if (distance < nonCollidingDistance) {
          const penetration = nonCollidingDistance - distance;
          const angle = Math.atan2(-deltaY, -deltaX);

          // This applies a large force to objects that are inside each other to make them stop touching.
          // You can think of this as a spring force.
          // This is an inaccurate approximation of actual collisions.

          const lesserMass = Math.min(objectA.mass, objectB.mass);
          const acceleration = 1 * penetration; // m/s/s
          // Force = Mass * Acceleration
          const force = lesserMass * acceleration;

          const springX = force * Math.cos(angle);
          const springY = force * Math.sin(angle);

          // Newton's third law: equal and opposite forces
          objectA.netForce.x += springX;
          objectA.netForce.y += springY;
          objectB.netForce.x -= springX;
          objectB.netForce.y -= springY;
        }

        // Universal gravitation
        // Fg = G * m1 * m2 / r^2
        const gravityMagnitude = G * objectA.mass * objectB.mass / (distance ** 2);

        // We have two similar right triangles:
        // 1) Hypotenuse = distance between points, legs = displacement between points
        // 2) Hypotenuse = force, legs = components of force
        // These equations were found using proportions
        const gravityX = deltaX * gravityMagnitude / distance;
        const gravityY = deltaY * gravityMagnitude / distance;

        // Newton's third law: equal and opposite forces
        objectA.netForce.x += gravityX;
        objectA.netForce.y += gravityY;
        objectB.netForce.x -= gravityX;
        objectB.netForce.y -= gravityY;
      }

      // All forces involving object A have been calculated, so we can move it.
      objectA.updateKinematics(this.timeStep);
    }

    this.dirty = true;
  }

  updateTrails() {
    if (this.running) {
      for (let i = 0; i < this.objects.length; i++) {
        const object = this.objects[i];
        object.trail.add(new TrailLocation(object.position.x, object.position.y, this.timestamp));
      }
    }
  }

  renderCursor() {
    if (this.interacting) {
      this.canvas.style.cursor = 'grabbing';
    } else {
      const hoveringObject = this.getObjectAtScreenPoint  (this.mouseClientX, this.mouseClientY);
      if (hoveringObject) {
        this.canvas.style.cursor = 'grab';
      } else {
        this.canvas.style.cursor = '';
      }
    }
  }

  render() {
    // Save power when not visible
    if (document.hidden) {
      return;
    }

    // Don't render if nothing changed
    if (!this.dirty) {
      return;
    }
    this.dirty = false;

    this.ctx.save();

    // Upscale for high-DPI screens
    this.ctx.scale(this.pixelRatio, this.pixelRatio);

    // Redraw background over old frame
    this.ctx.fillStyle = 'black';
    this.ctx.fillRect(0, 0, this.baseWidth, this.baseHeight);

    // Move (0, 0) to the center of the canvas
    this.ctx.translate(this.baseWidth / 2, this.baseHeight / 2);

    // Apply user zoom
    this.ctx.scale(this.zoom, this.zoom);

    // Apply user pan
    this.ctx.translate(-this.center.x, -this.center.y);

    const viewport = this.getSimulationViewport();

    this.ctx.lineWidth = this.calculateZoomIndependentPixels(3);
    this.ctx.lineCap = 'round';
    this.ctx.lineJoin = 'round';

    const sortedObjects = this.objects.slice().sort((a, b) => {
      if (a.locked && !b.locked) return 1;
      if (b.locked && !a.locked) return -1;
      return 0;
    });

    for (const object of sortedObjects) {
      this.ctx.save();

      const x = object.position.x;
      const y = object.position.y;

      if (object.getBounds().intersects(viewport)) {
        if (object.locked) {
          this.ctx.globalAlpha = 0.7;
        }
        this.ctx.fillStyle = object.color;
        this.ctx.beginPath();
        this.ctx.arc(x, y, object.radius, 0, 2 * Math.PI);
        this.ctx.fill();
        if (object.locked) {
          this.ctx.globalAlpha = 1;
        }
      }

      if (this.showTrails) {
        const points = object.trail.points;
        if (points.length > 0) {
          this.ctx.beginPath();
          this.ctx.strokeStyle = object.color;
          this.ctx.globalAlpha = 0.5;
          this.ctx.moveTo(points[0].x, points[0].y);
          for (let p = 1; p < points.length; p++) {
            const point = points[p];
            this.ctx.lineTo(point.x, point.y);
          }
          this.ctx.stroke();
          this.ctx.globalAlpha = 1;
        }
      }

      if (this.showVelocity && !object.locked) {
        this.ctx.beginPath();
        this.ctx.strokeStyle = 'rgb(0, 0, 255)';
        this.ctx.moveTo(x, y);
        this.ctx.lineTo(x + object.velocity.x * 1000, y + object.velocity.y * 1000);
        this.ctx.stroke();
      }

      if (this.showAcceleration && !object.locked) {
        this.ctx.beginPath();
        this.ctx.strokeStyle = 'rgb(255, 0, 0)';
        this.ctx.moveTo(x, y);
        this.ctx.lineTo(x + object.netForce.x / object.mass * 2000000, y + object.netForce.y / object.mass * 2000000);
        this.ctx.stroke();
      }

      this.ctx.restore();
    }

    this.ctx.restore();
  }

  pause() {
    this.running = false;
  }

  resume() {
    this.running = true;
  }

  toggleRunning() {
    if (this.running) {
      this.pause();
    } else {
      this.resume();
    }
  }

  getSpeedRelativeToRealtime() {
    // 1.0 means "realtime"
    // 2.0 means "twice as fast as realtime"
    // 0.0 means "not moving"
    // -1.0 means "realtime, but backwards"
    // 2.0 means "twice as fast as realtime, but backwards"
    return this.updatesPerSecond * this.timeStep;
  }

  setExponentialSpeed(exponentialSpeed) {
    const speedRelativeToRealtime = 1.5 ** Math.abs(exponentialSpeed);
    if (speedRelativeToRealtime > 1000) {
      this.timeStep = 0.1;
    } else {
      this.timeStep = 0.05;
    }
    this.timeStep *= Math.sign(exponentialSpeed) || 1;
    this.updatesPerSecond = Math.abs(speedRelativeToRealtime / this.timeStep);
  }

  loadPreset(name) {
    this.reset();

    if (name === 'earth') {
      this.addObject(earth.clone());
      this.addObject(moon.clone());
      this.addObject(iss.clone());

      this.center = earth.position.clone();
      this.zoom = 0.00001908570414305176;
    }

    if (name === 'ball-matrix') {
      this.addObject(earth.clone());

      for (let x = -3; x <= 3; x++) {
        for (let y = -3; y <= 3; y++) {
          const object = testObject
            .clone()
            .setColor(randomColor())
            .setPosition(0, 20000000)
            .moveBy(x * 2500000, y * 2500000);
          this.addObject(object);
        }
      }

      this.center = earth.position.clone();
      this.zoom = 0.00001908570414305176;
    }

    if (name === 'ball-orbit') {
      this.addObject(earth.clone());

      for (let y = 0; y < 20; y++) {
        const object = testObject
          .clone()
          .setColor(randomColor())
          .moveBy(0, y * 3500000)
          .setVelocity(2500, 0);
        this.addObject(object);
      }

      this.center = earth.position.clone();
      this.zoom = 0.000009154115588243545;
    }

    if (name === 'collision') {
      this.addObject(earth.clone());
      this.addObject(iss.clone());
      this.addObject(projectile.clone());

      this.center = new Vector(earth.radius * 0.3, -earth.radius);
      this.zoom = 0.0001197947197424044;
    }

    if (name === 'projectile') {
      this.addObject(earth.clone().setMass(earth.mass * 0.005).setUninteractable(true));
      this.addObject(smallProjectile);

      this.zoom = 0.1;
      this.center = smallProjectile.position.clone();
    }
  }

  startAnimationFrameLoop() {
    let focused = true;
    window.addEventListener('focus', () => {
      focused = true;
    });
    window.addEventListener('blur', () => {
      focused = false;
    });

    let previousTime = -1;
    const animationFrameCallback = (currentTime) => {
      requestAnimationFrame(animationFrameCallback);

      let deltaTimeMS = (previousTime === -1 || !focused) ? 0 : (currentTime - previousTime);
      previousTime = currentTime;
      deltaTimeMS = clamp(deltaTimeMS, 0, 30);
      const deltaTimeSeconds = deltaTimeMS / 1000;

      this.next(deltaTimeSeconds);
    };

    requestAnimationFrame(animationFrameCallback);
  }
}

const simulation = new Simulation();

const params = new URLSearchParams(location.search);

const earth = new PointMass()
  .setName('Earth')
  .setMass(5.972e24)
  .setRadius(6371000)
  .setColor('rgba(50, 255, 50)');

// const object = new PointMass()
//   .setMass(1)
//   .setRadius(1)
//   .setPosition(0, -earth.radius - 20);
// simulation.addObject(object)
const moon = new PointMass()
  .setName('Moon')
  .setMass(7.34767309e22)
  .setRadius(1737400)
  .setPosition(0, earth.radius + 378000000)
  .setVelocity(1028.192, 0);

const iss = new PointMass()
  .setName('ISS')
  .setMass(444615000)
  .setRadius(70000)
  .setPosition(0, earth.radius + 413000)
  .setVelocity(7660, 0)
  .setColor('rgba(127, 127, 255)');

const projectile = new PointMass()
  .setName('Projectile')
  .setMass(100)
  .setRadius(30000)
  .setPosition(0, -iss.position.y)
  .setVelocity(1000, 0);

const testObject = new PointMass()
  .setName('Big Rock')
  .setMass(4446150000)
  .setRadius(700000)
  .setPosition(0, earth.radius + 2000000);

const smallProjectile = new PointMass()
  .setName('Small Projectile')
  .setColor('white')
  .setMass(100)
  .setRadius(500)
  .setPosition(0, -earth.radius - 1000)
  .setVelocity(2, -15);

simulation.render();
simulation.startAnimationFrameLoop();
