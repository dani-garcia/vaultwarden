/*!
  * Native JavaScript for Bootstrap v4.0.4 (https://thednp.github.io/bootstrap.native/)
  * Copyright 2015-2021 © dnp_theme
  * Licensed under MIT (https://github.com/thednp/bootstrap.native/blob/master/LICENSE)
  */
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.BSN = factory());
}(this, (function () { 'use strict';

  const transitionEndEvent = 'webkitTransition' in document.head.style ? 'webkitTransitionEnd' : 'transitionend';

  const supportTransition = 'webkitTransition' in document.head.style || 'transition' in document.head.style;

  const transitionDuration = 'webkitTransition' in document.head.style ? 'webkitTransitionDuration' : 'transitionDuration';

  const transitionProperty = 'webkitTransition' in document.head.style ? 'webkitTransitionProperty' : 'transitionProperty';

  function getElementTransitionDuration(element) {
    const computedStyle = getComputedStyle(element);
    const propertyValue = computedStyle[transitionProperty];
    const durationValue = computedStyle[transitionDuration];
    const durationScale = durationValue.includes('ms') ? 1 : 1000;
    const duration = supportTransition && propertyValue && propertyValue !== 'none'
      ? parseFloat(durationValue) * durationScale : 0;

    return !Number.isNaN(duration) ? duration : 0;
  }

  function emulateTransitionEnd(element, handler) {
    let called = 0;
    const endEvent = new Event(transitionEndEvent);
    const duration = getElementTransitionDuration(element);

    if (duration) {
      element.addEventListener(transitionEndEvent, function transitionEndWrapper(e) {
        if (e.target === element) {
          handler.apply(element, [e]);
          element.removeEventListener(transitionEndEvent, transitionEndWrapper);
          called = 1;
        }
      });
      setTimeout(() => {
        if (!called) element.dispatchEvent(endEvent);
      }, duration + 17);
    } else {
      handler.apply(element, [endEvent]);
    }
  }

  function queryElement(selector, parent) {
    const lookUp = parent && parent instanceof Element ? parent : document;
    return selector instanceof Element ? selector : lookUp.querySelector(selector);
  }

  function hasClass(element, classNAME) {
    return element.classList.contains(classNAME);
  }

  function removeClass(element, classNAME) {
    element.classList.remove(classNAME);
  }

  const addEventListener = 'addEventListener';

  const removeEventListener = 'removeEventListener';

  const fadeClass = 'fade';

  const showClass = 'show';

  const dataBsDismiss = 'data-bs-dismiss';

  function bootstrapCustomEvent(namespacedEventType, eventProperties) {
    const OriginalCustomEvent = new CustomEvent(namespacedEventType, { cancelable: true });

    if (eventProperties instanceof Object) {
      Object.keys(eventProperties).forEach((key) => {
        Object.defineProperty(OriginalCustomEvent, key, {
          value: eventProperties[key],
        });
      });
    }
    return OriginalCustomEvent;
  }

  function normalizeValue(value) {
    if (value === 'true') {
      return true;
    }

    if (value === 'false') {
      return false;
    }

    if (!Number.isNaN(+value)) {
      return +value;
    }

    if (value === '' || value === 'null') {
      return null;
    }

    // string / function / Element / Object
    return value;
  }

  function normalizeOptions(element, defaultOps, inputOps, ns) {
    const normalOps = {};
    const dataOps = {};
    const data = { ...element.dataset };

    Object.keys(data)
      .forEach((k) => {
        const key = k.includes(ns)
          ? k.replace(ns, '').replace(/[A-Z]/, (match) => match.toLowerCase())
          : k;

        dataOps[key] = normalizeValue(data[k]);
      });

    Object.keys(inputOps)
      .forEach((k) => {
        inputOps[k] = normalizeValue(inputOps[k]);
      });

    Object.keys(defaultOps)
      .forEach((k) => {
        if (k in inputOps) {
          normalOps[k] = inputOps[k];
        } else if (k in dataOps) {
          normalOps[k] = dataOps[k];
        } else {
          normalOps[k] = defaultOps[k];
        }
      });

    return normalOps;
  }

  /* Native JavaScript for Bootstrap 5 | Base Component
  ----------------------------------------------------- */

  class BaseComponent {
    constructor(name, target, defaults, config) {
      const self = this;
      const element = queryElement(target);

      if (element[name]) element[name].dispose();
      self.element = element;

      if (defaults && Object.keys(defaults).length) {
        self.options = normalizeOptions(element, defaults, (config || {}), 'bs');
      }
      element[name] = self;
    }

    dispose(name) {
      const self = this;
      self.element[name] = null;
      Object.keys(self).forEach((prop) => { self[prop] = null; });
    }
  }

  /* Native JavaScript for Bootstrap 5 | Alert
  -------------------------------------------- */

  // ALERT PRIVATE GC
  // ================
  const alertString = 'alert';
  const alertComponent = 'Alert';
  const alertSelector = `.${alertString}`;
  const alertDismissSelector = `[${dataBsDismiss}="${alertString}"]`;

  // ALERT CUSTOM EVENTS
  // ===================
  const closeAlertEvent = bootstrapCustomEvent(`close.bs.${alertString}`);
  const closedAlertEvent = bootstrapCustomEvent(`closed.bs.${alertString}`);

  // ALERT EVENT HANDLERS
  // ====================
  function alertTransitionEnd(self) {
    const { element, relatedTarget } = self;
    toggleAlertHandler(self);

    if (relatedTarget) closedAlertEvent.relatedTarget = relatedTarget;
    element.dispatchEvent(closedAlertEvent);

    self.dispose();
    element.parentNode.removeChild(element);
  }

  // ALERT PRIVATE METHOD
  // ====================
  function toggleAlertHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    if (self.dismiss) self.dismiss[action]('click', self.close);
  }

  // ALERT DEFINITION
  // ================
  class Alert extends BaseComponent {
    constructor(target) {
      super(alertComponent, target);
      // bind
      const self = this;

      // initialization element
      const { element } = self;

      // the dismiss button
      self.dismiss = queryElement(alertDismissSelector, element);
      self.relatedTarget = null;

      // add event listener
      toggleAlertHandler(self, 1);
    }

    // ALERT PUBLIC METHODS
    // ====================
    close(e) {
      const target = e ? e.target : null;
      const self = e
        ? e.target.closest(alertSelector)[alertComponent]
        : this;
      const { element } = self;

      if (self && element && hasClass(element, showClass)) {
        if (target) {
          closeAlertEvent.relatedTarget = target;
          self.relatedTarget = target;
        }
        element.dispatchEvent(closeAlertEvent);
        if (closeAlertEvent.defaultPrevented) return;

        removeClass(element, showClass);

        if (hasClass(element, fadeClass)) {
          emulateTransitionEnd(element, () => alertTransitionEnd(self));
        } else alertTransitionEnd(self);
      }
    }

    dispose() {
      toggleAlertHandler(this);
      super.dispose(alertComponent);
    }
  }

  Alert.init = {
    component: alertComponent,
    selector: alertSelector,
    constructor: Alert,
  };

  function addClass(element, classNAME) {
    element.classList.add(classNAME);
  }

  const activeClass = 'active';

  const dataBsToggle = 'data-bs-toggle';

  /* Native JavaScript for Bootstrap 5 | Button
  ---------------------------------------------*/

  // BUTTON PRIVATE GC
  // =================
  const buttonString = 'button';
  const buttonComponent = 'Button';
  const buttonSelector = `[${dataBsToggle}="${buttonString}"]`;
  const ariaPressed = 'aria-pressed';

  // BUTTON PRIVATE METHOD
  // =====================
  function toggleButtonHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    self.element[action]('click', self.toggle);
  }

  // BUTTON DEFINITION
  // =================
  class Button extends BaseComponent {
    constructor(target) {
      super(buttonComponent, target);
      const self = this;

      // initialization element
      const { element } = self;

      // set initial state
      self.isActive = hasClass(element, activeClass);
      element.setAttribute(ariaPressed, !!self.isActive);

      // add event listener
      toggleButtonHandler(self, 1);
    }

    // BUTTON PUBLIC METHODS
    // =====================
    toggle(e) {
      if (e) e.preventDefault();
      const self = e ? this[buttonComponent] : this;
      const { element } = self;

      if (hasClass(element, 'disabled')) return;

      self.isActive = hasClass(element, activeClass);
      const { isActive } = self;

      const action = isActive ? removeClass : addClass;
      const ariaValue = isActive ? 'false' : 'true';

      action(element, activeClass);
      element.setAttribute(ariaPressed, ariaValue);
    }

    dispose() {
      toggleButtonHandler(this);
      super.dispose(buttonComponent);
    }
  }

  Button.init = {
    component: buttonComponent,
    selector: buttonSelector,
    constructor: Button,
  };

  const supportPassive = (() => {
    let result = false;
    try {
      const opts = Object.defineProperty({}, 'passive', {
        get() {
          result = true;
          return result;
        },
      });
      document[addEventListener]('DOMContentLoaded', function wrap() {
        document[removeEventListener]('DOMContentLoaded', wrap, opts);
      }, opts);
    } catch (e) {
      throw Error('Passive events are not supported');
    }

    return result;
  })();

  // general event options

  var passiveHandler = supportPassive ? { passive: true } : false;

  function reflow(element) {
    return element.offsetHeight;
  }

  function isElementInScrollRange(element) {
    const bcr = element.getBoundingClientRect();
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
    return bcr.top <= viewportHeight && bcr.bottom >= 0; // bottom && top
  }

  /* Native JavaScript for Bootstrap 5 | Carousel
  ----------------------------------------------- */

  // CAROUSEL PRIVATE GC
  // ===================
  const carouselString = 'carousel';
  const carouselComponent = 'Carousel';
  const carouselSelector = `[data-bs-ride="${carouselString}"]`;
  const carouselControl = `${carouselString}-control`;
  const carouselItem = `${carouselString}-item`;
  const dataBsSlideTo = 'data-bs-slide-to';
  const pausedClass = 'paused';
  const defaultCarouselOptions = {
    pause: 'hover', // 'boolean|string'
    keyboard: false, // 'boolean'
    touch: true, // 'boolean'
    interval: 5000, // 'boolean|number'
  };
  let startX = 0;
  let currentX = 0;
  let endX = 0;

  // CAROUSEL CUSTOM EVENTS
  // ======================
  const carouselSlideEvent = bootstrapCustomEvent(`slide.bs.${carouselString}`);
  const carouselSlidEvent = bootstrapCustomEvent(`slid.bs.${carouselString}`);

  // CAROUSEL EVENT HANDLERS
  // =======================
  function carouselTransitionEndHandler(self) {
    const {
      index, direction, element, slides, options, isAnimating,
    } = self;

    // discontinue disposed instances
    if (isAnimating && element[carouselComponent]) {
      const activeItem = getActiveIndex(self);
      const orientation = direction === 'left' ? 'next' : 'prev';
      const directionClass = direction === 'left' ? 'start' : 'end';
      self.isAnimating = false;

      addClass(slides[index], activeClass);
      removeClass(slides[activeItem], activeClass);

      removeClass(slides[index], `${carouselItem}-${orientation}`);
      removeClass(slides[index], `${carouselItem}-${directionClass}`);
      removeClass(slides[activeItem], `${carouselItem}-${directionClass}`);

      element.dispatchEvent(carouselSlidEvent);

      // check for element, might have been disposed
      if (!document.hidden && options.interval
        && !hasClass(element, pausedClass)) {
        self.cycle();
      }
    }
  }

  function carouselPauseHandler(e) {
    const eventTarget = e.target;
    const self = eventTarget.closest(carouselSelector)[carouselComponent];
    const { element, isAnimating } = self;

    if (!hasClass(element, pausedClass)) {
      addClass(element, pausedClass);
      if (!isAnimating) {
        clearInterval(self.timer);
        self.timer = null;
      }
    }
  }

  function carouselResumeHandler(e) {
    const eventTarget = e.target;
    const self = eventTarget.closest(carouselSelector)[carouselComponent];
    const { isPaused, isAnimating, element } = self;

    if (!isPaused && hasClass(element, pausedClass)) {
      removeClass(element, pausedClass);

      if (!isAnimating) {
        clearInterval(self.timer);
        self.timer = null;
        self.cycle();
      }
    }
  }

  function carouselIndicatorHandler(e) {
    e.preventDefault();
    const { target } = e;
    const self = target.closest(carouselSelector)[carouselComponent];

    if (self.isAnimating) return;

    const newIndex = target.getAttribute(dataBsSlideTo);

    if (target && !hasClass(target, activeClass) // event target is not active
      && newIndex) { // AND has the specific attribute
      self.to(+newIndex); // do the slide
    }
  }

  function carouselControlsHandler(e) {
    e.preventDefault();
    const that = this;
    const self = that.closest(carouselSelector)[carouselComponent];
    const { controls } = self;

    if (controls[1] && that === controls[1]) {
      self.next();
    } else if (controls[1] && that === controls[0]) {
      self.prev();
    }
  }

  function carouselKeyHandler({ which }) {
    const [element] = Array.from(document.querySelectorAll(carouselSelector))
      .filter((x) => isElementInScrollRange(x));

    if (!element) return;
    const self = element[carouselComponent];

    switch (which) {
      case 39:
        self.next();
        break;
      case 37:
        self.prev();
        break;
    }
  }

  // CAROUSEL TOUCH HANDLERS
  // =======================
  function carouselTouchDownHandler(e) {
    const element = this;
    const self = element[carouselComponent];

    if (!self || self.isTouch) { return; }

    startX = e.changedTouches[0].pageX;

    if (element.contains(e.target)) {
      self.isTouch = true;
      toggleCarouselTouchHandlers(self, 1);
    }
  }

  function carouselTouchMoveHandler(e) {
    const { changedTouches, type } = e;
    const self = this[carouselComponent];

    if (!self || !self.isTouch) { return; }

    currentX = changedTouches[0].pageX;

    // cancel touch if more than one changedTouches detected
    if (type === 'touchmove' && changedTouches.length > 1) {
      e.preventDefault();
    }
  }

  function carouselTouchEndHandler(e) {
    const element = this;
    const self = element[carouselComponent];

    if (!self || !self.isTouch) { return; }

    endX = currentX || e.changedTouches[0].pageX;

    if (self.isTouch) {
      // the event target is outside the carousel OR carousel doens't include the related target
      if ((!element.contains(e.target) || !element.contains(e.relatedTarget))
        && Math.abs(startX - endX) < 75) { // AND swipe distance is less than 75px
        // when the above conditions are satisfied, no need to continue
        return;
      } // OR determine next index to slide to
      if (currentX < startX) {
        self.index += 1;
      } else if (currentX > startX) {
        self.index -= 1;
      }

      self.isTouch = false;
      self.to(self.index); // do the slide

      toggleCarouselTouchHandlers(self); // remove touch events handlers
    }
  }

  // CAROUSEL PRIVATE METHODS
  // ========================
  function activateCarouselIndicator(self, pageIndex) { // indicators
    const { indicators } = self;
    Array.from(indicators).forEach((x) => removeClass(x, activeClass));
    if (self.indicators[pageIndex]) addClass(indicators[pageIndex], activeClass);
  }

  function toggleCarouselTouchHandlers(self, add) {
    const { element } = self;
    const action = add ? addEventListener : removeEventListener;
    element[action]('touchmove', carouselTouchMoveHandler, passiveHandler);
    element[action]('touchend', carouselTouchEndHandler, passiveHandler);
  }

  function toggleCarouselHandlers(self, add) {
    const {
      element, options, slides, controls, indicator,
    } = self;
    const {
      touch, pause, interval, keyboard,
    } = options;
    const action = add ? addEventListener : removeEventListener;

    if (pause && interval) {
      element[action]('mouseenter', carouselPauseHandler);
      element[action]('mouseleave', carouselResumeHandler);
      element[action]('touchstart', carouselPauseHandler, passiveHandler);
      element[action]('touchend', carouselResumeHandler, passiveHandler);
    }

    if (touch && slides.length > 1) {
      element[action]('touchstart', carouselTouchDownHandler, passiveHandler);
    }

    controls.forEach((arrow) => {
      if (arrow) arrow[action]('click', carouselControlsHandler);
    });

    if (indicator) indicator[action]('click', carouselIndicatorHandler);
    if (keyboard) window[action]('keydown', carouselKeyHandler);
  }

  function getActiveIndex(self) {
    const { slides, element } = self;
    return Array.from(slides)
      .indexOf(element.getElementsByClassName(`${carouselItem} ${activeClass}`)[0]) || 0;
  }

  // CAROUSEL DEFINITION
  // ===================
  class Carousel extends BaseComponent {
    constructor(target, config) {
      super(carouselComponent, target, defaultCarouselOptions, config);
      // bind
      const self = this;

      // additional properties
      self.timer = null;
      self.direction = 'left';
      self.isPaused = false;
      self.isAnimating = false;
      self.index = 0;
      self.timer = null;
      self.isTouch = false;

      // initialization element
      const { element } = self;
      // carousel elements
      // a LIVE collection is prefferable
      self.slides = element.getElementsByClassName(carouselItem);
      const { slides } = self;

      // invalidate when not enough items
      // no need to go further
      if (slides.length < 2) { return; }

      self.controls = [
        queryElement(`.${carouselControl}-prev`, element),
        queryElement(`.${carouselControl}-next`, element),
      ];

      // a LIVE collection is prefferable
      self.indicator = queryElement('.carousel-indicators', element);
      self.indicators = (self.indicator && self.indicator.querySelectorAll(`[${dataBsSlideTo}]`)) || [];

      // set JavaScript and DATA API options
      const { options } = self;

      // don't use TRUE as interval, it's actually 0, use the default 5000ms better
      self.options.interval = options.interval === true
        ? defaultCarouselOptions.interval
        : options.interval;

      // set first slide active if none
      if (getActiveIndex(self) < 0) {
        if (slides.length) addClass(slides[0], activeClass);
        if (self.indicators.length) activateCarouselIndicator(self, 0);
      }

      // attach event handlers
      toggleCarouselHandlers(self, 1);

      // start to cycle if interval is set
      if (options.interval) self.cycle();
    }

    // CAROUSEL PUBLIC METHODS
    // =======================
    cycle() {
      const self = this;
      const { isPaused, element, options } = self;
      if (self.timer) {
        clearInterval(self.timer);
        self.timer = null;
      }

      if (isPaused) {
        removeClass(element, pausedClass);
        self.isPaused = !isPaused;
      }

      self.timer = setInterval(() => {
        if (isElementInScrollRange(element)) {
          self.index += 1;
          self.to(self.index);
        }
      }, options.interval);
    }

    pause() {
      const self = this;
      const { element, options, isPaused } = self;
      if (options.interval && !isPaused) {
        clearInterval(self.timer);
        self.timer = null;
        addClass(element, pausedClass);
        self.isPaused = !isPaused;
      }
    }

    next() {
      const self = this;
      if (!self.isAnimating) { self.index += 1; self.to(self.index); }
    }

    prev() {
      const self = this;
      if (!self.isAnimating) { self.index -= 1; self.to(self.index); }
    }

    to(idx) {
      const self = this;
      const {
        element, isAnimating, slides, options,
      } = self;
      const activeItem = getActiveIndex(self);
      let next = idx;

      // when controled via methods, make sure to check again
      // first return if we're on the same item #227
      if (isAnimating || activeItem === next) return;

      // determine transition direction
      if ((activeItem < next) || (activeItem === 0 && next === slides.length - 1)) {
        self.direction = 'left'; // next
      } else if ((activeItem > next) || (activeItem === slides.length - 1 && next === 0)) {
        self.direction = 'right'; // prev
      }
      const { direction } = self;

      // find the right next index
      if (next < 0) { next = slides.length - 1; } else if (next >= slides.length) { next = 0; }

      // orientation, class name, eventProperties
      const orientation = direction === 'left' ? 'next' : 'prev';
      const directionClass = direction === 'left' ? 'start' : 'end';
      const eventProperties = {
        relatedTarget: slides[next], direction, from: activeItem, to: next,
      };

      // update event properties
      Object.keys(eventProperties).forEach((k) => {
        carouselSlideEvent[k] = eventProperties[k];
        carouselSlidEvent[k] = eventProperties[k];
      });

      // discontinue when prevented
      element.dispatchEvent(carouselSlideEvent);
      if (carouselSlideEvent.defaultPrevented) return;

      // update index
      self.index = next;

      clearInterval(self.timer);
      self.timer = null;

      self.isAnimating = true;
      activateCarouselIndicator(self, next);

      if (getElementTransitionDuration(slides[next]) && hasClass(element, 'slide')) {
        addClass(slides[next], `${carouselItem}-${orientation}`);
        reflow(slides[next]);
        addClass(slides[next], `${carouselItem}-${directionClass}`);
        addClass(slides[activeItem], `${carouselItem}-${directionClass}`);

        emulateTransitionEnd(slides[next], () => carouselTransitionEndHandler(self));
      } else {
        addClass(slides[next], activeClass);
        removeClass(slides[activeItem], activeClass);

        setTimeout(() => {
          self.isAnimating = false;

          // check for element, might have been disposed
          if (element && options.interval && !hasClass(element, pausedClass)) {
            self.cycle();
          }

          element.dispatchEvent(carouselSlidEvent);
        }, 100);
      }
    }

    dispose() {
      const self = this;
      const { slides } = self;
      const itemClasses = ['start', 'end', 'prev', 'next'];

      Array.from(slides).forEach((slide, idx) => {
        if (hasClass(slide, activeClass)) activateCarouselIndicator(self, idx);
        itemClasses.forEach((c) => removeClass(slide, `${carouselItem}-${c}`));
      });

      toggleCarouselHandlers(self);
      clearInterval(self.timer);
      super.dispose(carouselComponent);
    }
  }

  Carousel.init = {
    component: carouselComponent,
    selector: carouselSelector,
    constructor: Carousel,
  };

  const ariaExpanded = 'aria-expanded';

  // collapse / tab
  const collapsingClass = 'collapsing';

  const dataBsTarget = 'data-bs-target';

  const dataBsParent = 'data-bs-parent';

  const dataBsContainer = 'data-bs-container';

  function getTargetElement(element) {
    return queryElement(element.getAttribute(dataBsTarget) || element.getAttribute('href'))
          || element.closest(element.getAttribute(dataBsParent))
          || queryElement(element.getAttribute(dataBsContainer));
  }

  /* Native JavaScript for Bootstrap 5 | Collapse
  ----------------------------------------------- */

  // COLLAPSE GC
  // ===========
  const collapseString = 'collapse';
  const collapseComponent = 'Collapse';
  const collapseSelector = `.${collapseString}`;
  const collapseToggleSelector = `[${dataBsToggle}="${collapseString}"]`;

  // COLLAPSE CUSTOM EVENTS
  // ======================
  const showCollapseEvent = bootstrapCustomEvent(`show.bs.${collapseString}`);
  const shownCollapseEvent = bootstrapCustomEvent(`shown.bs.${collapseString}`);
  const hideCollapseEvent = bootstrapCustomEvent(`hide.bs.${collapseString}`);
  const hiddenCollapseEvent = bootstrapCustomEvent(`hidden.bs.${collapseString}`);

  // COLLAPSE PRIVATE METHODS
  // ========================
  function expandCollapse(self) {
    const {
      element, parent, triggers,
    } = self;

    element.dispatchEvent(showCollapseEvent);
    if (showCollapseEvent.defaultPrevented) return;

    self.isAnimating = true;
    if (parent) parent.isAnimating = true;

    addClass(element, collapsingClass);
    removeClass(element, collapseString);

    element.style.height = `${element.scrollHeight}px`;

    emulateTransitionEnd(element, () => {
      self.isAnimating = false;
      if (parent) parent.isAnimating = false;

      triggers.forEach((btn) => btn.setAttribute(ariaExpanded, 'true'));

      removeClass(element, collapsingClass);
      addClass(element, collapseString);
      addClass(element, showClass);

      element.style.height = '';

      element.dispatchEvent(shownCollapseEvent);
    });
  }

  function collapseContent(self) {
    const {
      element, parent, triggers,
    } = self;

    element.dispatchEvent(hideCollapseEvent);

    if (hideCollapseEvent.defaultPrevented) return;

    self.isAnimating = true;
    if (parent) parent.isAnimating = true;

    element.style.height = `${element.scrollHeight}px`;

    removeClass(element, collapseString);
    removeClass(element, showClass);
    addClass(element, collapsingClass);

    reflow(element);
    element.style.height = '0px';

    emulateTransitionEnd(element, () => {
      self.isAnimating = false;
      if (parent) parent.isAnimating = false;

      triggers.forEach((btn) => btn.setAttribute(ariaExpanded, 'false'));

      removeClass(element, collapsingClass);
      addClass(element, collapseString);

      element.style.height = '';

      element.dispatchEvent(hiddenCollapseEvent);
    });
  }

  function toggleCollapseHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    const { triggers } = self;

    if (triggers.length) {
      triggers.forEach((btn) => btn[action]('click', collapseClickHandler));
    }
  }

  // COLLAPSE EVENT HANDLER
  // ======================
  function collapseClickHandler(e) {
    const { target } = e;
    const trigger = target.closest(collapseToggleSelector);
    const element = getTargetElement(trigger);
    const self = element && element[collapseComponent];
    if (self) self.toggle(target);

    // event target is anchor link #398
    if (trigger && trigger.tagName === 'A') e.preventDefault();
  }

  // COLLAPSE DEFINITION
  // ===================
  class Collapse extends BaseComponent {
    constructor(target, config) {
      super(collapseComponent, target, { parent: null }, config);
      // bind
      const self = this;

      // initialization element
      const { element, options } = self;

      // set triggering elements
      self.triggers = Array.from(document.querySelectorAll(collapseToggleSelector))
        .filter((btn) => getTargetElement(btn) === element);

      // set parent accordion
      self.parent = queryElement(options.parent);
      const { parent } = self;

      // set initial state
      self.isAnimating = false;
      if (parent) parent.isAnimating = false;

      // add event listeners
      toggleCollapseHandler(self, 1);
    }

    // COLLAPSE PUBLIC METHODS
    // =======================
    toggle(related) {
      const self = this;
      if (!hasClass(self.element, showClass)) self.show(related);
      else self.hide(related);
    }

    hide() {
      const self = this;
      const { triggers, isAnimating } = self;
      if (isAnimating) return;

      collapseContent(self);
      if (triggers.length) {
        triggers.forEach((btn) => addClass(btn, `${collapseString}d`));
      }
    }

    show() {
      const self = this;
      const {
        element, parent, triggers, isAnimating,
      } = self;
      let activeCollapse;
      let activeCollapseInstance;

      if (parent) {
        activeCollapse = Array.from(parent.querySelectorAll(`.${collapseString}.${showClass}`))
          .find((i) => i[collapseComponent]);
        activeCollapseInstance = activeCollapse && activeCollapse[collapseComponent];
      }

      if ((!parent || (parent && !parent.isAnimating)) && !isAnimating) {
        if (activeCollapseInstance && activeCollapse !== element) {
          collapseContent(activeCollapseInstance);
          activeCollapseInstance.triggers.forEach((btn) => {
            addClass(btn, `${collapseString}d`);
          });
        }

        expandCollapse(self);
        if (triggers.length) {
          triggers.forEach((btn) => removeClass(btn, `${collapseString}d`));
        }
      }
    }

    dispose() {
      const self = this;
      const { parent } = self;
      toggleCollapseHandler(self);

      if (parent) delete parent.isAnimating;
      super.dispose(collapseComponent);
    }
  }

  Collapse.init = {
    component: collapseComponent,
    selector: collapseSelector,
    constructor: Collapse,
  };

  const dropdownMenuClasses = ['dropdown', 'dropup', 'dropstart', 'dropend'];

  const dropdownMenuClass = 'dropdown-menu';

  function isEmptyAnchor(elem) {
    const parentAnchor = elem.closest('A');
    // anchor href starts with #
    return elem && ((elem.href && elem.href.slice(-1) === '#')
      // OR a child of an anchor with href starts with #
      || (parentAnchor && parentAnchor.href && parentAnchor.href.slice(-1) === '#'));
  }

  function setFocus(element) {
    element.focus();
  }

  /* Native JavaScript for Bootstrap 5 | Dropdown
  ----------------------------------------------- */

  // DROPDOWN PRIVATE GC
  // ===================
  const [dropdownString] = dropdownMenuClasses;
  const dropdownComponent = 'Dropdown';
  const dropdownSelector = `[${dataBsToggle}="${dropdownString}"]`;

  // DROPDOWN PRIVATE GC
  // ===================
  const dropupString = dropdownMenuClasses[1];
  const dropstartString = dropdownMenuClasses[2];
  const dropendString = dropdownMenuClasses[3];
  const dropdownMenuEndClass = `${dropdownMenuClass}-end`;
  const hideMenuClass = ['d-block', 'invisible'];
  const verticalClass = [dropdownString, dropupString];
  const horizontalClass = [dropstartString, dropendString];
  const defaultDropdownOptions = {
    offset: 5, // [number] 5(px)
    display: 'dynamic', // [dynamic|static]
  };

  // DROPDOWN CUSTOM EVENTS
  // ========================
  const showDropdownEvent = bootstrapCustomEvent(`show.bs.${dropdownString}`);
  const shownDropdownEvent = bootstrapCustomEvent(`shown.bs.${dropdownString}`);
  const hideDropdownEvent = bootstrapCustomEvent(`hide.bs.${dropdownString}`);
  const hiddenDropdownEvent = bootstrapCustomEvent(`hidden.bs.${dropdownString}`);

  // DROPDOWN PRIVATE METHODS
  // ========================
  function styleDropdown(self, show) {
    const {
      element, menu, originalClass, menuEnd, options,
    } = self;
    const { offset } = options;
    const parent = element.parentElement;

    // reset menu offset and position
    const resetProps = ['margin', 'top', 'bottom', 'left', 'right'];
    resetProps.forEach((p) => { menu.style[p] = ''; });
    removeClass(parent, 'position-static');

    if (!show) {
      const menuEndNow = hasClass(menu, dropdownMenuEndClass);
      parent.className = originalClass.join(' ');
      if (menuEndNow && !menuEnd) removeClass(menu, dropdownMenuEndClass);
      else if (!menuEndNow && menuEnd) addClass(menu, dropdownMenuEndClass);
      return;
    }

    // set initial position class
    // take into account .btn-group parent as .dropdown
    let positionClass = dropdownMenuClasses.find((c) => originalClass.includes(c)) || dropdownString;

    let dropdownMargin = {
      dropdown: [offset, 0, 0],
      dropup: [0, 0, offset],
      dropstart: [-1, offset, 0],
      dropend: [-1, 0, 0, offset],
    };

    const dropdownPosition = {
      dropdown: { top: '100%' },
      dropup: { top: 'auto', bottom: '100%' },
      dropstart: { left: 'auto', right: '100%' },
      dropend: { left: '100%', right: 'auto' },
      menuEnd: { right: 0, left: 'auto' },
    };

    // force showing the menu to calculate its size
    hideMenuClass.forEach((c) => addClass(menu, c));

    const dropdownRegex = new RegExp(`\\b(${dropdownString}|${dropupString}|${dropstartString}|${dropendString})+`);
    const elementDimensions = { w: element.offsetWidth, h: element.offsetHeight };
    const menuDimensions = { w: menu.offsetWidth, h: menu.offsetHeight };
    const HTML = document.documentElement;
    const BD = document.body;
    const windowWidth = (HTML.clientWidth || BD.clientWidth);
    const windowHeight = (HTML.clientHeight || BD.clientHeight);
    const targetBCR = element.getBoundingClientRect();
    // dropdownMenuEnd && [ dropdown | dropup ]
    const leftExceed = targetBCR.left + elementDimensions.w - menuDimensions.w < 0;
    // dropstart
    const leftFullExceed = targetBCR.left - menuDimensions.w < 0;
    // !dropdownMenuEnd && [ dropdown | dropup ]
    const rightExceed = targetBCR.left + menuDimensions.w >= windowWidth;
    // dropend
    const rightFullExceed = targetBCR.left + menuDimensions.w + elementDimensions.w >= windowWidth;
    // dropstart | dropend
    const bottomExceed = targetBCR.top + menuDimensions.h >= windowHeight;
    // dropdown
    const bottomFullExceed = targetBCR.top + menuDimensions.h + elementDimensions.h >= windowHeight;
    // dropup
    const topExceed = targetBCR.top - menuDimensions.h < 0;

    // recompute position
    if (horizontalClass.includes(positionClass) && leftFullExceed && rightFullExceed) {
      positionClass = dropdownString;
    }
    if (horizontalClass.includes(positionClass) && bottomExceed) {
      positionClass = dropupString;
    }
    if (positionClass === dropstartString && leftFullExceed && !bottomExceed) {
      positionClass = dropendString;
    }
    if (positionClass === dropendString && rightFullExceed && !bottomExceed) {
      positionClass = dropstartString;
    }
    if (positionClass === dropupString && topExceed && !bottomFullExceed) {
      positionClass = dropdownString;
    }
    if (positionClass === dropdownString && bottomFullExceed && !topExceed) {
      positionClass = dropupString;
    }

    // set spacing
    dropdownMargin = dropdownMargin[positionClass];
    menu.style.margin = `${dropdownMargin.map((x) => (x ? `${x}px` : x)).join(' ')}`;
    Object.keys(dropdownPosition[positionClass]).forEach((position) => {
      menu.style[position] = dropdownPosition[positionClass][position];
    });

    // update dropdown position class
    if (!hasClass(parent, positionClass)) {
      parent.className = parent.className.replace(dropdownRegex, positionClass);
    }

    // update dropdown / dropup to handle parent btn-group element
    // as well as the dropdown-menu-end utility class
    if (verticalClass.includes(positionClass)) {
      if (!menuEnd && rightExceed) addClass(menu, dropdownMenuEndClass);
      else if (menuEnd && leftExceed) removeClass(menu, dropdownMenuEndClass);

      if (hasClass(menu, dropdownMenuEndClass)) {
        Object.keys(dropdownPosition.menuEnd).forEach((p) => {
          menu.style[p] = dropdownPosition.menuEnd[p];
        });
      }
    }

    // remove util classes from the menu, we have its size
    hideMenuClass.forEach((c) => removeClass(menu, c));
  }

  function toggleDropdownDismiss(self) {
    const action = self.open ? addEventListener : removeEventListener;

    document[action]('click', dropdownDismissHandler);
    document[action]('focus', dropdownDismissHandler);
    document[action]('keydown', dropdownPreventScroll);
    document[action]('keyup', dropdownKeyHandler);

    if (self.options.display === 'dynamic') {
      window[action]('scroll', dropdownLayoutHandler, passiveHandler);
      window[action]('resize', dropdownLayoutHandler, passiveHandler);
    }
  }

  function toggleDropdownHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    self.element[action]('click', dropdownClickHandler);
  }

  function getCurrentOpenDropdown() {
    const currentParent = dropdownMenuClasses.concat('btn-group')
      .map((c) => document.getElementsByClassName(`${c} ${showClass}`))
      .find((x) => x.length);

    if (currentParent && currentParent.length) {
      return Array.from(currentParent[0].children).find((x) => x.hasAttribute(dataBsToggle));
    }
    return null;
  }

  // DROPDOWN EVENT HANDLERS
  // =======================
  function dropdownDismissHandler(e) {
    const { target, type } = e;
    if (!target.closest) return; // some weird FF bug #409

    const element = getCurrentOpenDropdown();
    const parent = element && element.parentNode;
    const self = element && element[dropdownComponent];
    const menu = self && self.menu;

    const hasData = target.closest(dropdownSelector) !== null;
    const isForm = parent && parent.contains(target)
      && (target.tagName === 'form' || target.closest('form') !== null);

    if (type === 'click' && isEmptyAnchor(target)) {
      e.preventDefault();
    }
    if (type === 'focus'
      && (target === element || target === menu || menu.contains(target))) {
      return;
    }

    if (isForm || hasData) ; else if (self) {
      self.hide(element);
    }
  }

  function dropdownClickHandler(e) {
    const element = this;
    const self = element[dropdownComponent];
    self.toggle(element);

    if (isEmptyAnchor(e.target)) e.preventDefault();
  }

  function dropdownPreventScroll(e) {
    if (e.which === 38 || e.which === 40) e.preventDefault();
  }

  function dropdownKeyHandler({ which }) {
    const element = getCurrentOpenDropdown();
    const self = element[dropdownComponent];
    const { menu, menuItems, open } = self;
    const activeItem = document.activeElement;
    const isSameElement = activeItem === element;
    const isInsideMenu = menu.contains(activeItem);
    const isMenuItem = activeItem.parentNode === menu || activeItem.parentNode.parentNode === menu;

    let idx = menuItems.indexOf(activeItem);

    if (isMenuItem) { // navigate up | down
      if (isSameElement) {
        idx = 0;
      } else if (which === 38) {
        idx = idx > 1 ? idx - 1 : 0;
      } else if (which === 40) {
        idx = idx < menuItems.length - 1 ? idx + 1 : idx;
      }

      if (menuItems[idx]) setFocus(menuItems[idx]);
    }

    if (((menuItems.length && isMenuItem) // menu has items
        || (!menuItems.length && (isInsideMenu || isSameElement)) // menu might be a form
        || !isInsideMenu) // or the focused element is not in the menu at all
        && open && which === 27 // menu must be open
    ) {
      self.toggle();
    }
  }

  function dropdownLayoutHandler() {
    const element = getCurrentOpenDropdown();
    const self = element && element[dropdownComponent];

    if (self && self.open) styleDropdown(self, 1);
  }

  // DROPDOWN DEFINITION
  // ===================
  class Dropdown extends BaseComponent {
    constructor(target, config) {
      super(dropdownComponent, target, defaultDropdownOptions, config);
      // bind
      const self = this;

      // initialization element
      const { element } = self;

      // set targets
      const parent = element.parentElement;
      self.menu = queryElement(`.${dropdownMenuClass}`, parent);
      const { menu } = self;

      self.originalClass = Array.from(parent.classList);

      // set original position
      self.menuEnd = hasClass(menu, dropdownMenuEndClass);

      self.menuItems = [];

      Array.from(menu.children).forEach((child) => {
        if (child.children.length && (child.children[0].tagName === 'A')) self.menuItems.push(child.children[0]);
        if (child.tagName === 'A') self.menuItems.push(child);
      });

      // set initial state to closed
      self.open = false;

      // add event listener
      toggleDropdownHandler(self, 1);
    }

    // DROPDOWN PUBLIC METHODS
    // =======================
    toggle(related) {
      const self = this;
      const { open } = self;

      if (open) self.hide(related);
      else self.show(related);
    }

    show(related) {
      const self = this;
      const currentParent = queryElement(dropdownMenuClasses.concat('btn-group').map((c) => `.${c}.${showClass}`).join(','));
      const currentElement = currentParent && queryElement(dropdownSelector, currentParent);

      if (currentElement) currentElement[dropdownComponent].hide();

      const { element, menu, open } = self;
      const parent = element.parentNode;

      // update relatedTarget and dispatch
      showDropdownEvent.relatedTarget = related || null;
      parent.dispatchEvent(showDropdownEvent);
      if (showDropdownEvent.defaultPrevented) return;

      // change menu position
      styleDropdown(self, 1);

      addClass(menu, showClass);
      addClass(parent, showClass);

      element.setAttribute(ariaExpanded, true);
      self.open = !open;

      setTimeout(() => {
        setFocus(menu.getElementsByTagName('INPUT')[0] || element); // focus the first input item | element
        toggleDropdownDismiss(self);

        shownDropdownEvent.relatedTarget = related || null;
        parent.dispatchEvent(shownDropdownEvent);
      }, 1);
    }

    hide(related) {
      const self = this;
      const { element, menu, open } = self;
      const parent = element.parentNode;
      hideDropdownEvent.relatedTarget = related || null;
      parent.dispatchEvent(hideDropdownEvent);
      if (hideDropdownEvent.defaultPrevented) return;

      removeClass(menu, showClass);
      removeClass(parent, showClass);

      // revert to original position
      styleDropdown(self);

      element.setAttribute(ariaExpanded, false);
      self.open = !open;

      setFocus(element);

      // only re-attach handler if the instance is not disposed
      setTimeout(() => toggleDropdownDismiss(self), 1);

      // update relatedTarget and dispatch
      hiddenDropdownEvent.relatedTarget = related || null;
      parent.dispatchEvent(hiddenDropdownEvent);
    }

    dispose() {
      const self = this;
      const { element } = self;

      if (hasClass(element.parentNode, showClass) && self.open) self.hide();

      toggleDropdownHandler(self);

      super.dispose(dropdownComponent);
    }
  }

  Dropdown.init = {
    component: dropdownComponent,
    selector: dropdownSelector,
    constructor: Dropdown,
  };

  const ariaHidden = 'aria-hidden';

  const ariaModal = 'aria-modal';

  const fixedTopClass = 'fixed-top';

  const fixedBottomClass = 'fixed-bottom';

  const stickyTopClass = 'sticky-top';

  const fixedItems = Array.from(document.getElementsByClassName(fixedTopClass))
    .concat(Array.from(document.getElementsByClassName(fixedBottomClass)))
    .concat(Array.from(document.getElementsByClassName(stickyTopClass)))
    .concat(Array.from(document.getElementsByClassName('is-fixed')));

  function resetScrollbar() {
    const bd = document.body;
    bd.style.paddingRight = '';
    bd.style.overflow = '';

    if (fixedItems.length) {
      fixedItems.forEach((fixed) => {
        fixed.style.paddingRight = '';
        fixed.style.marginRight = '';
      });
    }
  }

  function measureScrollbar() {
    const windowWidth = document.documentElement.clientWidth;
    return Math.abs(window.innerWidth - windowWidth);
  }

  function setScrollbar(scrollbarWidth, overflow) {
    const bd = document.body;
    const bdStyle = getComputedStyle(bd);
    const bodyPad = parseInt(bdStyle.paddingRight, 10);
    const isOpen = bdStyle.overflow === 'hidden';
    const sbWidth = isOpen && bodyPad ? 0 : scrollbarWidth;

    if (overflow) {
      bd.style.overflow = 'hidden';
      bd.style.paddingRight = `${bodyPad + sbWidth}px`;

      if (fixedItems.length) {
        fixedItems.forEach((fixed) => {
          const isSticky = hasClass(fixed, stickyTopClass);
          const itemPadValue = getComputedStyle(fixed).paddingRight;
          fixed.style.paddingRight = `${parseInt(itemPadValue, 10) + sbWidth}px`;
          if (isSticky) {
            const itemMValue = getComputedStyle(fixed).marginRight;
            fixed.style.marginRight = `${parseInt(itemMValue, 10) - sbWidth}px`;
          }
        });
      }
    }
  }

  const modalOpenClass = 'modal-open';
  const modalBackdropClass = 'modal-backdrop';
  const modalActiveSelector = `.modal.${showClass}`;
  const offcanvasActiveSelector = `.offcanvas.${showClass}`;

  const overlay = document.createElement('div');
  overlay.setAttribute('class', `${modalBackdropClass}`);

  function getCurrentOpen() {
    return queryElement(`${modalActiveSelector},${offcanvasActiveSelector}`);
  }

  function appendOverlay(hasFade) {
    document.body.appendChild(overlay);
    if (hasFade) addClass(overlay, fadeClass);
  }

  function showOverlay() {
    addClass(overlay, showClass);
    reflow(overlay);
  }

  function hideOverlay() {
    removeClass(overlay, showClass);
  }

  function removeOverlay() {
    const bd = document.body;
    const currentOpen = getCurrentOpen();

    if (!currentOpen) {
      removeClass(overlay, fadeClass);
      removeClass(bd, modalOpenClass);
      bd.removeChild(overlay);
      resetScrollbar();
    }
  }

  function isVisible(element) {
    return getComputedStyle(element).visibility !== 'hidden'
      && element.offsetParent !== null;
  }

  /* Native JavaScript for Bootstrap 5 | Modal
  -------------------------------------------- */

  // MODAL PRIVATE GC
  // ================
  const modalString = 'modal';
  const modalComponent = 'Modal';
  const modalSelector = `.${modalString}`;
  // const modalActiveSelector = `.${modalString}.${showClass}`;
  const modalToggleSelector = `[${dataBsToggle}="${modalString}"]`;
  const modalDismissSelector = `[${dataBsDismiss}="${modalString}"]`;
  const modalStaticClass = `${modalString}-static`;
  const modalDefaultOptions = {
    backdrop: true, // boolean|string
    keyboard: true, // boolean
  };

  // MODAL CUSTOM EVENTS
  // ===================
  const showModalEvent = bootstrapCustomEvent(`show.bs.${modalString}`);
  const shownModalEvent = bootstrapCustomEvent(`shown.bs.${modalString}`);
  const hideModalEvent = bootstrapCustomEvent(`hide.bs.${modalString}`);
  const hiddenModalEvent = bootstrapCustomEvent(`hidden.bs.${modalString}`);

  // MODAL PRIVATE METHODS
  // =====================
  function setModalScrollbar(self) {
    const { element, scrollbarWidth } = self;
    const bd = document.body;
    const html = document.documentElement;
    const bodyOverflow = html.clientHeight !== html.scrollHeight
                      || bd.clientHeight !== bd.scrollHeight;
    const modalOverflow = element.clientHeight !== element.scrollHeight;

    if (!modalOverflow && scrollbarWidth) {
      element.style.paddingRight = `${scrollbarWidth}px`;
    }
    setScrollbar(scrollbarWidth, (modalOverflow || bodyOverflow));
  }

  function toggleModalDismiss(self, add) {
    const action = add ? addEventListener : removeEventListener;
    window[action]('resize', self.update, passiveHandler);
    self.element[action]('click', modalDismissHandler);
    document[action]('keydown', modalKeyHandler);
  }

  function toggleModalHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    const { triggers } = self;

    if (triggers.length) {
      triggers.forEach((btn) => btn[action]('click', modalClickHandler));
    }
  }

  function afterModalHide(self) {
    const { triggers } = self;
    removeOverlay();
    self.element.style.paddingRight = '';
    self.isAnimating = false;

    if (triggers.length) {
      const visibleTrigger = triggers.find((x) => isVisible(x));
      if (visibleTrigger) setFocus(visibleTrigger);
    }
  }

  function afterModalShow(self) {
    const { element, relatedTarget } = self;
    setFocus(element);
    self.isAnimating = false;

    toggleModalDismiss(self, 1);

    shownModalEvent.relatedTarget = relatedTarget;
    element.dispatchEvent(shownModalEvent);
  }

  function beforeModalShow(self) {
    const { element, hasFade } = self;
    element.style.display = 'block';

    setModalScrollbar(self);
    if (!queryElement(modalActiveSelector)) {
      document.body.style.overflow = 'hidden';
      addClass(document.body, modalOpenClass);
    }

    addClass(element, showClass);
    element.removeAttribute(ariaHidden);
    element.setAttribute(ariaModal, true);

    if (hasFade) emulateTransitionEnd(element, () => afterModalShow(self));
    else afterModalShow(self);
  }

  function beforeModalHide(self, force) {
    const {
      element, relatedTarget, hasFade,
    } = self;
    const currentOpen = getCurrentOpen();

    element.style.display = '';

    // force can also be the transitionEvent object, we wanna make sure it's not
    // call is not forced and overlay is visible
    if (!force && hasFade && hasClass(overlay, showClass)
      && !currentOpen) { // AND no modal is visible
      hideOverlay();
      emulateTransitionEnd(overlay, () => afterModalHide(self));
    } else {
      afterModalHide(self);
    }

    toggleModalDismiss(self);

    hiddenModalEvent.relatedTarget = relatedTarget;
    element.dispatchEvent(hiddenModalEvent);
  }

  // MODAL EVENT HANDLERS
  // ====================
  function modalClickHandler(e) {
    const { target } = e;
    const trigger = target.closest(modalToggleSelector);
    const element = getTargetElement(trigger);
    const self = element && element[modalComponent];

    if (trigger.tagName === 'A') e.preventDefault();

    if (self.isAnimating) return;

    self.relatedTarget = trigger;

    self.toggle();
  }

  function modalKeyHandler({ which }) {
    const element = queryElement(modalActiveSelector);
    const self = element[modalComponent];
    const { options, isAnimating } = self;
    if (!isAnimating // modal has no animations running
      && options.keyboard && which === 27 // the keyboard option is enabled and the key is 27
      && hasClass(element, showClass)) { // the modal is not visible
      self.relatedTarget = null;
      self.hide();
    }
  }

  function modalDismissHandler(e) {
    const element = this;
    const self = element[modalComponent];

    if (self.isAnimating) return;

    const { isStatic, modalDialog } = self;
    const { target } = e;
    const selectedText = document.getSelection().toString().length;
    const targetInsideDialog = modalDialog.contains(target);
    const dismiss = target.closest(modalDismissSelector);

    if (isStatic && !targetInsideDialog) {
      addClass(element, modalStaticClass);
      self.isAnimating = true;
      emulateTransitionEnd(modalDialog, () => staticTransitionEnd(self));
    } else if (dismiss || (!selectedText && !isStatic && !targetInsideDialog)) {
      self.relatedTarget = dismiss || null;
      self.hide();
      e.preventDefault();
    }
  }

  function staticTransitionEnd(self) {
    const duration = getElementTransitionDuration(self.modalDialog) + 17;
    removeClass(self.element, modalStaticClass);
    // user must wait for zoom out transition
    setTimeout(() => { self.isAnimating = false; }, duration);
  }

  // MODAL DEFINITION
  // ================
  class Modal extends BaseComponent {
    constructor(target, config) {
      super(modalComponent, target, modalDefaultOptions, config);

      // bind
      const self = this;

      // the modal
      const { element } = self;

      // the modal-dialog
      self.modalDialog = queryElement(`.${modalString}-dialog`, element);

      // modal can have multiple triggering elements
      self.triggers = Array.from(document.querySelectorAll(modalToggleSelector))
        .filter((btn) => getTargetElement(btn) === element);

      // additional internals
      self.isStatic = self.options.backdrop === 'static';
      self.hasFade = hasClass(element, fadeClass);
      self.isAnimating = false;
      self.scrollbarWidth = measureScrollbar();
      self.relatedTarget = null;

      // attach event listeners
      toggleModalHandler(self, 1);

      // bind
      self.update = self.update.bind(self);
    }

    // MODAL PUBLIC METHODS
    // ====================
    toggle() {
      const self = this;
      if (hasClass(self.element, showClass)) self.hide();
      else self.show();
    }

    show() {
      const self = this;
      const {
        element, isAnimating, hasFade, relatedTarget,
      } = self;
      let overlayDelay = 0;

      if (hasClass(element, showClass) && !isAnimating) return;

      showModalEvent.relatedTarget = relatedTarget || null;
      element.dispatchEvent(showModalEvent);
      if (showModalEvent.defaultPrevented) return;

      self.isAnimating = true;

      // we elegantly hide any opened modal/offcanvas
      const currentOpen = getCurrentOpen();
      if (currentOpen && currentOpen !== element) {
        const that = currentOpen[modalComponent]
          ? currentOpen[modalComponent]
          : currentOpen.Offcanvas;
        that.hide();
      }

      if (!queryElement(`.${modalBackdropClass}`)) {
        appendOverlay(hasFade);
      }
      overlayDelay = getElementTransitionDuration(overlay);

      if (!hasClass(overlay, showClass)) {
        showOverlay();
      }

      if (!currentOpen) {
        setTimeout(() => beforeModalShow(self), overlayDelay);
      } else beforeModalShow(self);
    }

    hide(force) {
      const self = this;
      const {
        element, isAnimating, hasFade, relatedTarget,
      } = self;
      if (!hasClass(element, showClass) && !isAnimating) return;

      hideModalEvent.relatedTarget = relatedTarget || null;
      element.dispatchEvent(hideModalEvent);
      if (hideModalEvent.defaultPrevented) return;

      self.isAnimating = true;
      removeClass(element, showClass);
      element.setAttribute(ariaHidden, true);
      element.removeAttribute(ariaModal);

      if (hasFade && force !== 1) {
        emulateTransitionEnd(element, () => beforeModalHide(self));
      } else {
        beforeModalHide(self, force);
      }
    }

    update() {
      const self = this;

      if (hasClass(self.element, showClass)) setModalScrollbar(self);
    }

    dispose() {
      const self = this;
      self.hide(1); // forced call

      toggleModalHandler(self);

      super.dispose(modalComponent);
    }
  }

  Modal.init = {
    component: modalComponent,
    selector: modalSelector,
    constructor: Modal,
  };

  /* Native JavaScript for Bootstrap 5 | OffCanvas
  ------------------------------------------------ */

  // OFFCANVAS PRIVATE GC
  // ====================
  const offcanvasString = 'offcanvas';
  const offcanvasComponent = 'Offcanvas';
  const OffcanvasSelector = `.${offcanvasString}`;
  const offcanvasToggleSelector = `[${dataBsToggle}="${offcanvasString}"]`;
  const offcanvasDismissSelector = `[${dataBsDismiss}="${offcanvasString}"]`;
  const offcanvasTogglingClass = `${offcanvasString}-toggling`;
  const offcanvasDefaultOptions = {
    backdrop: true, // boolean
    keyboard: true, // boolean
    scroll: false, // boolean
  };

  // OFFCANVAS CUSTOM EVENTS
  // =======================
  const showOffcanvasEvent = bootstrapCustomEvent(`show.bs.${offcanvasString}`);
  const shownOffcanvasEvent = bootstrapCustomEvent(`shown.bs.${offcanvasString}`);
  const hideOffcanvasEvent = bootstrapCustomEvent(`hide.bs.${offcanvasString}`);
  const hiddenOffcanvasEvent = bootstrapCustomEvent(`hidden.bs.${offcanvasString}`);

  // OFFCANVAS PRIVATE METHODS
  // =========================
  function setOffCanvasScrollbar(self) {
    const bd = document.body;
    const html = document.documentElement;
    const bodyOverflow = html.clientHeight !== html.scrollHeight
                      || bd.clientHeight !== bd.scrollHeight;
    setScrollbar(self.scrollbarWidth, bodyOverflow);
  }

  function toggleOffcanvasEvents(self, add) {
    const action = add ? addEventListener : removeEventListener;
    self.triggers.forEach((btn) => btn[action]('click', offcanvasTriggerHandler));
  }

  function toggleOffCanvasDismiss(add) {
    const action = add ? addEventListener : removeEventListener;
    document[action]('keydown', offcanvasKeyDismissHandler);
    document[action]('click', offcanvasDismissHandler);
  }

  function beforeOffcanvasShow(self) {
    const { element, options } = self;

    if (!options.scroll) {
      addClass(document.body, modalOpenClass);
      document.body.style.overflow = 'hidden';
      setOffCanvasScrollbar(self);
    }

    addClass(element, offcanvasTogglingClass);
    addClass(element, showClass);
    element.style.visibility = 'visible';

    emulateTransitionEnd(element, () => showOffcanvasComplete(self));
  }

  function beforeOffcanvasHide(self) {
    const { element, options } = self;
    const currentOpen = getCurrentOpen();

    element.blur();

    if (!currentOpen && options.backdrop && hasClass(overlay, showClass)) {
      hideOverlay();
      emulateTransitionEnd(overlay, () => hideOffcanvasComplete(self));
    } else hideOffcanvasComplete(self);
  }

  // OFFCANVAS EVENT HANDLERS
  // ========================
  function offcanvasTriggerHandler(e) {
    const trigger = this.closest(offcanvasToggleSelector);
    const element = getTargetElement(trigger);
    const self = element && element[offcanvasComponent];

    if (trigger.tagName === 'A') e.preventDefault();
    if (self) {
      self.relatedTarget = trigger;
      self.toggle();
    }
  }

  function offcanvasDismissHandler(e) {
    const element = queryElement(offcanvasActiveSelector);
    if (!element) return;

    const offCanvasDismiss = queryElement(offcanvasDismissSelector, element);
    const self = element[offcanvasComponent];
    if (!self) return;

    const { options, open, triggers } = self;
    const { target } = e;
    const trigger = target.closest(offcanvasToggleSelector);

    if (trigger && trigger.tagName === 'A') e.preventDefault();

    if (open && ((!element.contains(target) && options.backdrop
      && (!trigger || (trigger && !triggers.includes(trigger))))
      || offCanvasDismiss.contains(target))) {
      self.relatedTarget = target === offCanvasDismiss ? offCanvasDismiss : null;
      self.hide();
    }
  }

  function offcanvasKeyDismissHandler({ which }) {
    const element = queryElement(offcanvasActiveSelector);
    if (!element) return;

    const self = element[offcanvasComponent];

    if (self && self.options.keyboard && which === 27) {
      self.relatedTarget = null;
      self.hide();
    }
  }

  function showOffcanvasComplete(self) {
    const { element, triggers, relatedTarget } = self;
    removeClass(element, offcanvasTogglingClass);

    element.removeAttribute(ariaHidden);
    element.setAttribute(ariaModal, true);
    element.setAttribute('role', 'dialog');
    self.isAnimating = false;

    if (triggers.length) {
      triggers.forEach((btn) => btn.setAttribute(ariaExpanded, true));
    }

    shownOffcanvasEvent.relatedTarget = relatedTarget || null;
    element.dispatchEvent(shownOffcanvasEvent);

    toggleOffCanvasDismiss(1);
    setFocus(element);
  }

  function hideOffcanvasComplete(self) {
    const {
      element, options, relatedTarget, triggers,
    } = self;
    const currentOpen = getCurrentOpen();

    element.setAttribute(ariaHidden, true);
    element.removeAttribute(ariaModal);
    element.removeAttribute('role');
    element.style.visibility = '';
    self.open = false;
    self.isAnimating = false;

    if (triggers.length) {
      triggers.forEach((btn) => btn.setAttribute(ariaExpanded, false));
      const visibleTrigger = triggers.find((x) => isVisible(x));
      if (visibleTrigger) setFocus(visibleTrigger);
    }

    // handle new offcanvas showing up
    if (!currentOpen) {
      if (options.backdrop) removeOverlay();
      if (!options.scroll) {
        resetScrollbar();
        removeClass(document.body, modalOpenClass);
      }
    }

    hiddenOffcanvasEvent.relatedTarget = relatedTarget || null;
    element.dispatchEvent(hiddenOffcanvasEvent);
    removeClass(element, offcanvasTogglingClass);

    toggleOffCanvasDismiss();
  }

  // OFFCANVAS DEFINITION
  // ====================
  class Offcanvas extends BaseComponent {
    constructor(target, config) {
      super(offcanvasComponent, target, offcanvasDefaultOptions, config);
      const self = this;

      // instance element
      const { element } = self;

      // all the triggering buttons
      self.triggers = Array.from(document.querySelectorAll(offcanvasToggleSelector))
        .filter((btn) => getTargetElement(btn) === element);

      // additional instance property
      self.open = false;
      self.isAnimating = false;
      self.scrollbarWidth = measureScrollbar();

      // attach event listeners
      toggleOffcanvasEvents(self, 1);
    }

    // OFFCANVAS PUBLIC METHODS
    // ========================
    toggle() {
      const self = this;
      return self.open ? self.hide() : self.show();
    }

    show() {
      const self = this[offcanvasComponent] ? this[offcanvasComponent] : this;
      const {
        element, options, isAnimating, relatedTarget,
      } = self;
      let overlayDelay = 0;

      if (self.open || isAnimating) return;

      showOffcanvasEvent.relatedTarget = relatedTarget || null;
      element.dispatchEvent(showOffcanvasEvent);

      if (showOffcanvasEvent.defaultPrevented) return;

      // we elegantly hide any opened modal/offcanvas
      const currentOpen = getCurrentOpen();
      if (currentOpen && currentOpen !== element) {
        const that = currentOpen[offcanvasComponent]
          ? currentOpen[offcanvasComponent]
          : currentOpen.Modal;
        that.hide();
      }

      self.open = true;
      self.isAnimating = true;

      if (options.backdrop) {
        if (!queryElement(`.${modalBackdropClass}`)) {
          appendOverlay(1);
        }

        overlayDelay = getElementTransitionDuration(overlay);

        if (!hasClass(overlay, showClass)) showOverlay();

        setTimeout(() => beforeOffcanvasShow(self), overlayDelay);
      } else beforeOffcanvasShow(self);
    }

    hide(force) {
      const self = this;
      const { element, isAnimating, relatedTarget } = self;

      if (!self.open || isAnimating) return;

      hideOffcanvasEvent.relatedTarget = relatedTarget || null;
      element.dispatchEvent(hideOffcanvasEvent);
      if (hideOffcanvasEvent.defaultPrevented) return;

      self.isAnimating = true;
      addClass(element, offcanvasTogglingClass);
      removeClass(element, showClass);

      if (!force) {
        emulateTransitionEnd(element, () => beforeOffcanvasHide(self));
      } else beforeOffcanvasHide(self);
    }

    dispose() {
      const self = this;
      self.hide(1);
      toggleOffcanvasEvents(self);
      super.dispose(offcanvasComponent);
    }
  }

  Offcanvas.init = {
    component: offcanvasComponent,
    selector: OffcanvasSelector,
    constructor: Offcanvas,
  };

  const ariaDescribedBy = 'aria-describedby';

  var tipClassPositions = {
    top: 'top', bottom: 'bottom', left: 'start', right: 'end',
  };

  function isVisibleTip(tip, container) {
    return container.contains(tip);
  }

  function isMedia(element) {
    return [SVGElement, HTMLImageElement, HTMLVideoElement]
      .some((mediaType) => element instanceof mediaType);
  }

  function closestRelative(element) {
    let retval = null;
    let el = element;
    while (el !== document.body) {
      el = el.parentElement;
      if (getComputedStyle(el).position === 'relative') {
        retval = el;
        break;
      }
    }
    return retval;
  }

  // both popovers and tooltips (this, event)
  function styleTip(self, e) {
    const tipClasses = /\b(top|bottom|start|end)+/;
    const tip = self.tooltip || self.popover;
    // reset tip style
    tip.style.top = '';
    tip.style.left = '';
    tip.style.right = '';
    // continue with metrics
    const isPopover = !!self.popover;
    let tipDimensions = { w: tip.offsetWidth, h: tip.offsetHeight };
    const windowWidth = (document.documentElement.clientWidth || document.body.clientWidth);
    const windowHeight = (document.documentElement.clientHeight || document.body.clientHeight);
    const { element, options, arrow } = self;
    let { container, placement } = options;
    let parentIsBody = container === document.body;
    const targetPosition = getComputedStyle(element).position;
    const parentPosition = getComputedStyle(container).position;
    const staticParent = !parentIsBody && parentPosition === 'static';
    let relativeParent = !parentIsBody && parentPosition === 'relative';
    const relContainer = staticParent && closestRelative(container);
    // static containers should refer to another relative container or the body
    container = relContainer || container;
    relativeParent = staticParent && relContainer ? 1 : relativeParent;
    parentIsBody = container === document.body;
    const parentRect = container.getBoundingClientRect();
    const leftBoundry = relativeParent ? parentRect.left : 0;
    const rightBoundry = relativeParent ? parentRect.right : windowWidth;
    // this case should not be possible
    // absoluteParent = !parentIsBody && parentPosition === 'absolute',
    // this case requires a container with placement: relative
    const absoluteTarget = targetPosition === 'absolute';
    const targetRect = element.getBoundingClientRect();
    const scroll = parentIsBody
      ? { x: window.pageXOffset, y: window.pageYOffset }
      : { x: container.scrollLeft, y: container.scrollTop };
    const elemDimensions = { w: element.offsetWidth, h: element.offsetHeight };
    const top = relativeParent ? element.offsetTop : targetRect.top;
    const left = relativeParent ? element.offsetLeft : targetRect.left;
    // reset arrow style
    arrow.style.top = '';
    arrow.style.left = '';
    arrow.style.right = '';
    let topPosition;
    let leftPosition;
    let rightPosition;
    let arrowTop;
    let arrowLeft;
    let arrowRight;

    // check placement
    let topExceed = targetRect.top - tipDimensions.h < 0;
    let bottomExceed = targetRect.top + tipDimensions.h + elemDimensions.h >= windowHeight;
    let leftExceed = targetRect.left - tipDimensions.w < leftBoundry;
    let rightExceed = targetRect.left + tipDimensions.w + elemDimensions.w >= rightBoundry;

    topExceed = ['left', 'right'].includes(placement)
      ? targetRect.top + elemDimensions.h / 2 - tipDimensions.h / 2 < 0
      : topExceed;
    bottomExceed = ['left', 'right'].includes(placement)
      ? targetRect.top + tipDimensions.h / 2 + elemDimensions.h / 2 >= windowHeight
      : bottomExceed;
    leftExceed = ['top', 'bottom'].includes(placement)
      ? targetRect.left + elemDimensions.w / 2 - tipDimensions.w / 2 < leftBoundry
      : leftExceed;
    rightExceed = ['top', 'bottom'].includes(placement)
      ? targetRect.left + tipDimensions.w / 2 + elemDimensions.w / 2 >= rightBoundry
      : rightExceed;

    // recompute placement
    // first, when both left and right limits are exceeded, we fall back to top|bottom
    placement = (['left', 'right'].includes(placement)) && leftExceed && rightExceed ? 'top' : placement;
    placement = placement === 'top' && topExceed ? 'bottom' : placement;
    placement = placement === 'bottom' && bottomExceed ? 'top' : placement;
    placement = placement === 'left' && leftExceed ? 'right' : placement;
    placement = placement === 'right' && rightExceed ? 'left' : placement;

    // update tooltip/popover class
    if (!tip.className.includes(placement)) {
      tip.className = tip.className.replace(tipClasses, tipClassPositions[placement]);
    }
    // if position has changed, update tip dimensions
    tipDimensions = { w: tip.offsetWidth, h: tip.offsetHeight };

    // we check the computed width & height and update here
    const arrowWidth = arrow.offsetWidth || 0;
    const arrowHeight = arrow.offsetHeight || 0;
    const arrowAdjust = arrowWidth / 2;

    // compute tooltip / popover coordinates
    if (['left', 'right'].includes(placement)) { // secondary|side positions
      if (placement === 'left') { // LEFT
        leftPosition = left + scroll.x - tipDimensions.w - (isPopover ? arrowWidth : 0);
      } else { // RIGHT
        leftPosition = left + scroll.x + elemDimensions.w + (isPopover ? arrowWidth : 0);
      }

      // adjust top and arrow
      if (topExceed) {
        topPosition = top + scroll.y;
        arrowTop = elemDimensions.h / 2 - arrowWidth;
      } else if (bottomExceed) {
        topPosition = top + scroll.y - tipDimensions.h + elemDimensions.h;
        arrowTop = tipDimensions.h - elemDimensions.h / 2 - arrowWidth;
      } else {
        topPosition = top + scroll.y - tipDimensions.h / 2 + elemDimensions.h / 2;
        arrowTop = tipDimensions.h / 2 - arrowHeight / 2;
      }
    } else if (['top', 'bottom'].includes(placement)) {
      if (e && isMedia(element)) {
        const eX = !relativeParent ? e.pageX : e.layerX + (absoluteTarget ? element.offsetLeft : 0);
        const eY = !relativeParent ? e.pageY : e.layerY + (absoluteTarget ? element.offsetTop : 0);

        if (placement === 'top') {
          topPosition = eY - tipDimensions.h - (isPopover ? arrowWidth : arrowHeight);
        } else {
          topPosition = eY + arrowHeight;
        }

        // adjust left | right and also the arrow
        if (e.clientX - tipDimensions.w / 2 < leftBoundry) { // when exceeds left
          leftPosition = 0;
          arrowLeft = eX - arrowAdjust;
        } else if (e.clientX + tipDimensions.w * 0.51 >= rightBoundry) { // when exceeds right
          leftPosition = 'auto';
          rightPosition = 0;
          arrowLeft = tipDimensions.w - (rightBoundry - eX) - arrowAdjust;
        } else { // normal top/bottom
          leftPosition = eX - tipDimensions.w / 2;
          arrowLeft = tipDimensions.w / 2 - arrowAdjust;
        }
      } else {
        if (placement === 'top') {
          topPosition = top + scroll.y - tipDimensions.h - (isPopover ? arrowHeight : 0);
        } else { // BOTTOM
          topPosition = top + scroll.y + elemDimensions.h + (isPopover ? arrowHeight : 0);
        }

        // adjust left | right and also the arrow
        if (leftExceed) {
          leftPosition = 0;
          arrowLeft = left + elemDimensions.w / 2 - arrowAdjust;
        } else if (rightExceed) {
          leftPosition = 'auto';
          rightPosition = 0;
          arrowRight = elemDimensions.w / 2 + (parentRect.right - targetRect.right) - arrowAdjust;
        } else {
          leftPosition = left + scroll.x - tipDimensions.w / 2 + elemDimensions.w / 2;
          arrowLeft = tipDimensions.w / 2 - arrowAdjust;
        }
      }
    }

    // apply style to tooltip/popover and its arrow
    tip.style.top = `${topPosition}px`;
    tip.style.left = leftPosition === 'auto' ? leftPosition : `${leftPosition}px`;
    tip.style.right = rightPosition !== undefined ? `${rightPosition}px` : '';
    // update arrow placement or clear side
    if (arrowTop !== undefined) {
      arrow.style.top = `${arrowTop}px`;
    }

    if (arrowLeft !== undefined) {
      arrow.style.left = `${arrowLeft}px`;
    } else if (arrowRight !== undefined) {
      arrow.style.right = `${arrowRight}px`;
    }
  }

  let bsnUID = 1;

  // popover, tooltip, scrollspy need a unique id
  function getUID(element, key) {
    bsnUID += 1;
    return element[key] || bsnUID;
  }

  function getTipContainer(element) {
    // maybe the element is inside a modal
    const modal = element.closest('.modal');

    // OR maybe the element is inside a fixed navbar
    const navbarFixed = element.closest(`.${fixedTopClass},.${fixedBottomClass}`);

    // set default container option appropriate for the context
    return modal || navbarFixed || document.body;
  }

  /* Native JavaScript for Bootstrap 5 | Popover
  ---------------------------------------------- */

  // POPOVER PRIVATE GC
  // ==================
  const popoverString = 'popover';
  const popoverComponent = 'Popover';
  const popoverSelector = `[${dataBsToggle}="${popoverString}"],[data-tip="${popoverString}"]`;
  const popoverDefaultOptions = {
    template: '<div class="popover" role="tooltip"><div class="popover-arrow"></div><h3 class="popover-header"></h3><div class="popover-body"></div></div>', // string
    title: null, // string
    content: null, // string
    sanitizeFn: null, // function
    customClass: null, // string
    dismissible: false, // boolean
    animation: true, // boolean
    trigger: 'hover', // string
    placement: 'top', // string
    delay: 200, // number
  };

  // POPOVER PRIVATE GC
  // ==================
  const appleBrands = /(iPhone|iPod|iPad)/;
  const isIphone = navigator.userAgentData
    ? navigator.userAgentData.brands.some((x) => appleBrands.test(x.brand))
    : appleBrands.test(navigator.userAgent);
  // popoverArrowClass = `${popoverString}-arrow`,
  const popoverHeaderClass = `${popoverString}-header`;
  const popoverBodyClass = `${popoverString}-body`;
  // close btn for dissmissible popover
  let popoverCloseButton = '<button type="button" class="btn-close"></button>';

  // POPOVER CUSTOM EVENTS
  // =====================
  const showPopoverEvent = bootstrapCustomEvent(`show.bs.${popoverString}`);
  const shownPopoverEvent = bootstrapCustomEvent(`shown.bs.${popoverString}`);
  const hidePopoverEvent = bootstrapCustomEvent(`hide.bs.${popoverString}`);
  const hiddenPopoverEvent = bootstrapCustomEvent(`hidden.bs.${popoverString}`);

  // POPOVER EVENT HANDLERS
  // ======================
  function popoverForceFocus() {
    setFocus(this);
  }

  function popoverTouchHandler({ target }) {
    const self = this;
    const { popover, element } = self;

    if ((popover && popover.contains(target)) // popover includes touch target
      || target === element // OR touch target is element
      || element.contains(target)) ; else {
      self.hide();
    }
  }

  // POPOVER PRIVATE METHODS
  // =======================
  function createPopover(self) {
    const { id, options } = self;
    const {
      animation, customClass, sanitizeFn, placement, dismissible,
    } = options;
    let { title, content, template } = options;

    // set initial popover class
    const placementClass = `bs-${popoverString}-${tipClassPositions[placement]}`;

    // fixing #233
    title = title ? title.trim() : null;
    content = content ? content.trim() : null;

    // sanitize title && content
    if (sanitizeFn) {
      title = title ? sanitizeFn(title) : null;
      content = content ? sanitizeFn(content) : null;
      template = template ? sanitizeFn(template) : null;
      popoverCloseButton = sanitizeFn(popoverCloseButton);
    }

    self.popover = document.createElement('div');
    const { popover } = self;

    // set id and aria-describedby
    popover.setAttribute('id', id);
    popover.setAttribute('role', 'tooltip');

    // load template
    const popoverTemplate = document.createElement('div');
    popoverTemplate.innerHTML = template.trim();
    popover.className = popoverTemplate.firstChild.className;
    popover.innerHTML = popoverTemplate.firstChild.innerHTML;

    const popoverHeader = queryElement(`.${popoverHeaderClass}`, popover);
    const popoverBody = queryElement(`.${popoverBodyClass}`, popover);

    // set arrow
    self.arrow = queryElement(`.${popoverString}-arrow`, popover);

    // set dismissible button
    if (dismissible) {
      title = title ? title + popoverCloseButton : title;
      content = title === null ? +popoverCloseButton : content;
    }

    // fill the template with content from data attributes
    if (title && popoverHeader) popoverHeader.innerHTML = title.trim();
    if (content && popoverBody) popoverBody.innerHTML = content.trim();

    // set popover animation and placement
    if (!hasClass(popover, popoverString)) addClass(popover, popoverString);
    if (animation && !hasClass(popover, fadeClass)) addClass(popover, fadeClass);
    if (customClass && !hasClass(popover, customClass)) {
      addClass(popover, customClass);
    }
    if (!hasClass(popover, placementClass)) addClass(popover, placementClass);
  }

  function removePopover(self) {
    const { element, popover, options } = self;
    element.removeAttribute(ariaDescribedBy);
    options.container.removeChild(popover);
    self.timer = null;
  }

  function togglePopoverHandlers(self, add) {
    const action = add ? addEventListener : removeEventListener;
    const { element, options } = self;
    const { trigger, dismissible } = options;
    self.enabled = !!add;

    if (trigger === 'hover') {
      element[action]('mousedown', self.show);
      element[action]('mouseenter', self.show);
      if (isMedia(element)) element[action]('mousemove', self.update, passiveHandler);
      if (!dismissible) element[action]('mouseleave', self.hide);
    } else if (trigger === 'click') {
      element[action](trigger, self.toggle);
    } else if (trigger === 'focus') {
      if (isIphone) element[action]('click', popoverForceFocus);
      element[action]('focusin', self.show);
    }
  }

  function dismissHandlerToggle(self, add) {
    const action = add ? addEventListener : removeEventListener;
    const { options, element, popover } = self;
    const { trigger, dismissible } = options;

    if (dismissible) {
      const [btnClose] = popover.getElementsByClassName('btn-close');
      if (btnClose) btnClose[action]('click', self.hide);
    } else {
      if (trigger === 'focus') element[action]('focusout', self.hide);
      if (trigger === 'hover') document[action]('touchstart', popoverTouchHandler, passiveHandler);
    }

    if (!isMedia(element)) {
      window[action]('scroll', self.update, passiveHandler);
      window[action]('resize', self.update, passiveHandler);
    }
  }

  function popoverShowTrigger(self) {
    dismissHandlerToggle(self, 1);
    self.element.dispatchEvent(shownPopoverEvent);
  }

  function popoverHideTrigger(self) {
    dismissHandlerToggle(self);
    removePopover(self);
    self.element.dispatchEvent(hiddenPopoverEvent);
  }

  // POPOVER DEFINITION
  // ==================
  class Popover extends BaseComponent {
    constructor(target, config) {
      popoverDefaultOptions.container = getTipContainer(queryElement(target));
      super(popoverComponent, target, popoverDefaultOptions, config);

      // bind
      const self = this;

      // initialization element
      const { element } = self;
      // additional instance properties
      self.timer = null;
      self.popover = null;
      self.arrow = null;
      self.enabled = false;
      // set unique ID for aria-describedby
      self.id = `${popoverString}-${getUID(element)}`;

      // set instance options
      const { options } = self;

      // media elements only work with body as a container
      self.options.container = isMedia(element)
        ? popoverDefaultOptions.container
        : queryElement(options.container);

      // reset default container
      popoverDefaultOptions.container = null;

      // invalidate when no content is set
      if (!options.content) return;

      // crate popover
      createPopover(self);

      // bind
      self.update = self.update.bind(self);

      // attach event listeners
      togglePopoverHandlers(self, 1);
    }

    update(e) {
      styleTip(this, e);
    }

    // POPOVER PUBLIC METHODS
    // ======================
    toggle(e) {
      const self = e ? this[popoverComponent] : this;
      const { popover, options } = self;
      if (!isVisibleTip(popover, options.container)) self.show();
      else self.hide();
    }

    show(e) {
      const self = e ? this[popoverComponent] : this;
      const {
        element, popover, options, id,
      } = self;
      const { container } = options;

      clearTimeout(self.timer);

      self.timer = setTimeout(() => {
        if (!isVisibleTip(popover, container)) {
          element.dispatchEvent(showPopoverEvent);
          if (showPopoverEvent.defaultPrevented) return;

          // append to the container
          container.appendChild(popover);
          element.setAttribute(ariaDescribedBy, id);

          self.update(e);
          if (!hasClass(popover, showClass)) addClass(popover, showClass);

          if (options.animation) emulateTransitionEnd(popover, () => popoverShowTrigger(self));
          else popoverShowTrigger(self);
        }
      }, 17);
    }

    hide(e) {
      let self;
      if (e && this[popoverComponent]) {
        self = this[popoverComponent];
      } else if (e) { // dismissible popover
        const dPopover = this.closest(`.${popoverString}`);
        const dEl = dPopover && queryElement(`[${ariaDescribedBy}="${dPopover.id}"]`);
        self = dEl[popoverComponent];
      } else {
        self = this;
      }
      const { element, popover, options } = self;

      clearTimeout(self.timer);

      self.timer = setTimeout(() => {
        if (isVisibleTip(popover, options.container)) {
          element.dispatchEvent(hidePopoverEvent);
          if (hidePopoverEvent.defaultPrevented) return;

          removeClass(popover, showClass);

          if (options.animation) emulateTransitionEnd(popover, () => popoverHideTrigger(self));
          else popoverHideTrigger(self);
        }
      }, options.delay + 17);
    }

    enable() {
      const self = this;
      const { enabled } = self;
      if (!enabled) {
        togglePopoverHandlers(self, 1);
        self.enabled = !enabled;
      }
    }

    disable() {
      const self = this;
      const { enabled, popover, options } = self;
      if (enabled) {
        if (isVisibleTip(popover, options.container) && options.animation) {
          self.hide();

          setTimeout(
            () => togglePopoverHandlers(self),
            getElementTransitionDuration(popover) + options.delay + 17,
          );
        } else {
          togglePopoverHandlers(self);
        }
        self.enabled = !enabled;
      }
    }

    toggleEnabled() {
      const self = this;
      if (!self.enabled) self.enable();
      else self.disable();
    }

    dispose() {
      const self = this;
      const { popover, options } = self;
      const { container, animation } = options;
      if (animation && isVisibleTip(popover, container)) {
        options.delay = 0; // reset delay
        self.hide();
        emulateTransitionEnd(popover, () => togglePopoverHandlers(self));
      } else {
        togglePopoverHandlers(self);
      }
      super.dispose(popoverComponent);
    }
  }

  Popover.init = {
    component: popoverComponent,
    selector: popoverSelector,
    constructor: Popover,
  };

  /* Native JavaScript for Bootstrap 5 | ScrollSpy
  ------------------------------------------------ */

  // SCROLLSPY PRIVATE GC
  // ====================
  const scrollspyString = 'scrollspy';
  const scrollspyComponent = 'ScrollSpy';
  const scrollspySelector = '[data-bs-spy="scroll"]';
  const scrollSpyDefaultOptions = {
    offset: 10,
    target: null,
  };

  // SCROLLSPY CUSTOM EVENT
  // ======================
  const activateScrollSpy = bootstrapCustomEvent(`activate.bs.${scrollspyString}`);

  // SCROLLSPY PRIVATE METHODS
  // =========================
  function updateSpyTargets(self) {
    const {
      target, scrollTarget, isWindow, options, itemsLength, scrollHeight,
    } = self;
    const { offset } = options;
    const links = target.getElementsByTagName('A');

    self.scrollTop = isWindow
      ? scrollTarget.pageYOffset
      : scrollTarget.scrollTop;

    // only update items/offsets once or with each mutation
    if (itemsLength !== links.length || getScrollHeight(scrollTarget) !== scrollHeight) {
      let href;
      let targetItem;
      let rect;

      // reset arrays & update
      self.items = [];
      self.offsets = [];
      self.scrollHeight = getScrollHeight(scrollTarget);
      self.maxScroll = self.scrollHeight - getOffsetHeight(self);

      Array.from(links).forEach((link) => {
        href = link.getAttribute('href');
        targetItem = href && href.charAt(0) === '#' && href.slice(-1) !== '#' && queryElement(href);

        if (targetItem) {
          self.items.push(link);
          rect = targetItem.getBoundingClientRect();
          self.offsets.push((isWindow ? rect.top + self.scrollTop : targetItem.offsetTop) - offset);
        }
      });
      self.itemsLength = self.items.length;
    }
  }

  function getScrollHeight(scrollTarget) {
    return scrollTarget.scrollHeight || Math.max(
      document.body.scrollHeight,
      document.documentElement.scrollHeight,
    );
  }

  function getOffsetHeight({ element, isWindow }) {
    if (!isWindow) return element.getBoundingClientRect().height;
    return window.innerHeight;
  }

  function clear(target) {
    Array.from(target.getElementsByTagName('A')).forEach((item) => {
      if (hasClass(item, activeClass)) removeClass(item, activeClass);
    });
  }

  function activate(self, item) {
    const { target, element } = self;
    clear(target);
    self.activeItem = item;
    addClass(item, activeClass);

    // activate all parents
    const parents = [];
    let parentItem = item;
    while (parentItem !== document.body) {
      parentItem = parentItem.parentNode;
      if (hasClass(parentItem, 'nav') || hasClass(parentItem, 'dropdown-menu')) parents.push(parentItem);
    }

    parents.forEach((menuItem) => {
      const parentLink = menuItem.previousElementSibling;

      if (parentLink && !hasClass(parentLink, activeClass)) {
        addClass(parentLink, activeClass);
      }
    });

    // update relatedTarget and dispatch
    activateScrollSpy.relatedTarget = item;
    element.dispatchEvent(activateScrollSpy);
  }

  function toggleSpyHandlers(self, add) {
    const action = add ? addEventListener : removeEventListener;
    self.scrollTarget[action]('scroll', self.refresh, passiveHandler);
  }

  // SCROLLSPY DEFINITION
  // ====================
  class ScrollSpy extends BaseComponent {
    constructor(target, config) {
      super(scrollspyComponent, target, scrollSpyDefaultOptions, config);
      // bind
      const self = this;

      // initialization element & options
      const { element, options } = self;

      // additional properties
      self.target = queryElement(options.target);

      // invalidate
      if (!self.target) return;

      // set initial state
      self.scrollTarget = element.clientHeight < element.scrollHeight ? element : window;
      self.isWindow = self.scrollTarget === window;
      self.scrollTop = 0;
      self.maxScroll = 0;
      self.scrollHeight = 0;
      self.activeItem = null;
      self.items = [];
      self.offsets = [];

      // bind events
      self.refresh = self.refresh.bind(self);

      // add event handlers
      toggleSpyHandlers(self, 1);

      self.refresh();
    }

    // SCROLLSPY PUBLIC METHODS
    // ========================
    refresh() {
      const self = this;
      const { target } = self;

      // check if target is visible and invalidate
      if (target.offsetHeight === 0) return;

      updateSpyTargets(self);

      const {
        scrollTop, maxScroll, itemsLength, items, activeItem,
      } = self;

      if (scrollTop >= maxScroll) {
        const newActiveItem = items[itemsLength - 1];

        if (activeItem !== newActiveItem) {
          activate(self, newActiveItem);
        }
        return;
      }

      const { offsets } = self;

      if (activeItem && scrollTop < offsets[0] && offsets[0] > 0) {
        self.activeItem = null;
        clear(target);
        return;
      }

      items.forEach((item, i) => {
        if (activeItem !== item && scrollTop >= offsets[i]
          && (typeof offsets[i + 1] === 'undefined' || scrollTop < offsets[i + 1])) {
          activate(self, item);
        }
      });
    }

    dispose() {
      toggleSpyHandlers(this);
      super.dispose(scrollspyComponent);
    }
  }

  ScrollSpy.init = {
    component: scrollspyComponent,
    selector: scrollspySelector,
    constructor: ScrollSpy,
  };

  const ariaSelected = 'aria-selected';

  /* Native JavaScript for Bootstrap 5 | Tab
  ------------------------------------------ */

  // TAB PRIVATE GC
  // ================
  const tabString = 'tab';
  const tabComponent = 'Tab';
  const tabSelector = `[${dataBsToggle}="${tabString}"]`;

  // TAB CUSTOM EVENTS
  // =================
  const showTabEvent = bootstrapCustomEvent(`show.bs.${tabString}`);
  const shownTabEvent = bootstrapCustomEvent(`shown.bs.${tabString}`);
  const hideTabEvent = bootstrapCustomEvent(`hide.bs.${tabString}`);
  const hiddenTabEvent = bootstrapCustomEvent(`hidden.bs.${tabString}`);

  let nextTab;
  let nextTabContent;
  let nextTabHeight;
  let activeTab;
  let activeTabContent;
  let tabContainerHeight;
  let tabEqualContents;

  // TAB PRIVATE METHODS
  // ===================
  function triggerTabEnd(self) {
    const { tabContent, nav } = self;
    tabContent.style.height = '';
    removeClass(tabContent, collapsingClass);
    nav.isAnimating = false;
  }

  function triggerTabShow(self) {
    const { tabContent, nav } = self;

    if (tabContent) { // height animation
      if (tabEqualContents) {
        triggerTabEnd(self);
      } else {
        setTimeout(() => { // enables height animation
          tabContent.style.height = `${nextTabHeight}px`; // height animation
          reflow(tabContent);
          emulateTransitionEnd(tabContent, () => triggerTabEnd(self));
        }, 50);
      }
    } else {
      nav.isAnimating = false;
    }
    shownTabEvent.relatedTarget = activeTab;
    nextTab.dispatchEvent(shownTabEvent);
  }

  function triggerTabHide(self) {
    const { tabContent } = self;
    if (tabContent) {
      activeTabContent.style.float = 'left';
      nextTabContent.style.float = 'left';
      tabContainerHeight = activeTabContent.scrollHeight;
    }

    // update relatedTarget and dispatch event
    showTabEvent.relatedTarget = activeTab;
    hiddenTabEvent.relatedTarget = nextTab;
    nextTab.dispatchEvent(showTabEvent);
    if (showTabEvent.defaultPrevented) return;

    addClass(nextTabContent, activeClass);
    removeClass(activeTabContent, activeClass);

    if (tabContent) {
      nextTabHeight = nextTabContent.scrollHeight;
      tabEqualContents = nextTabHeight === tabContainerHeight;
      addClass(tabContent, collapsingClass);
      tabContent.style.height = `${tabContainerHeight}px`; // height animation
      reflow(tabContent);
      activeTabContent.style.float = '';
      nextTabContent.style.float = '';
    }

    if (hasClass(nextTabContent, fadeClass)) {
      setTimeout(() => {
        addClass(nextTabContent, showClass);
        emulateTransitionEnd(nextTabContent, () => {
          triggerTabShow(self);
        });
      }, 20);
    } else { triggerTabShow(self); }

    activeTab.dispatchEvent(hiddenTabEvent);
  }

  function getActiveTab({ nav }) {
    const activeTabs = nav.getElementsByClassName(activeClass);

    if (activeTabs.length === 1
      && !dropdownMenuClasses.some((c) => hasClass(activeTabs[0].parentNode, c))) {
      [activeTab] = activeTabs;
    } else if (activeTabs.length > 1) {
      activeTab = activeTabs[activeTabs.length - 1];
    }
    return activeTab;
  }

  function getActiveTabContent(self) {
    return queryElement(getActiveTab(self).getAttribute('href'));
  }

  function toggleTabHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    self.element[action]('click', tabClickHandler);
  }

  // TAB EVENT HANDLER
  // =================
  function tabClickHandler(e) {
    const self = this[tabComponent];
    e.preventDefault();
    if (!self.nav.isAnimating) self.show();
  }

  // TAB DEFINITION
  // ==============
  class Tab extends BaseComponent {
    constructor(target) {
      super(tabComponent, target);
      // bind
      const self = this;

      // initialization element
      const { element } = self;

      // event targets
      self.nav = element.closest('.nav');
      const { nav } = self;
      self.dropdown = nav && queryElement(`.${dropdownMenuClasses[0]}-toggle`, nav);
      activeTabContent = getActiveTabContent(self);
      self.tabContent = supportTransition && activeTabContent.closest('.tab-content');
      tabContainerHeight = activeTabContent.scrollHeight;

      // set default animation state
      nav.isAnimating = false;

      // add event listener
      toggleTabHandler(self, 1);
    }

    // TAB PUBLIC METHODS
    // ==================
    show() { // the tab we clicked is now the nextTab tab
      const self = this;
      const { element, nav, dropdown } = self;
      nextTab = element;
      if (!hasClass(nextTab, activeClass)) {
        // this is the actual object, the nextTab tab content to activate
        nextTabContent = queryElement(nextTab.getAttribute('href'));
        activeTab = getActiveTab({ nav });
        activeTabContent = getActiveTabContent({ nav });

        // update relatedTarget and dispatch
        hideTabEvent.relatedTarget = nextTab;
        activeTab.dispatchEvent(hideTabEvent);
        if (hideTabEvent.defaultPrevented) return;

        nav.isAnimating = true;
        removeClass(activeTab, activeClass);
        activeTab.setAttribute(ariaSelected, 'false');
        addClass(nextTab, activeClass);
        nextTab.setAttribute(ariaSelected, 'true');

        if (dropdown) {
          if (!hasClass(element.parentNode, dropdownMenuClass)) {
            if (hasClass(dropdown, activeClass)) removeClass(dropdown, activeClass);
          } else if (!hasClass(dropdown, activeClass)) addClass(dropdown, activeClass);
        }

        if (hasClass(activeTabContent, fadeClass)) {
          removeClass(activeTabContent, showClass);
          emulateTransitionEnd(activeTabContent, () => triggerTabHide(self));
        } else {
          triggerTabHide(self);
        }
      }
    }

    dispose() {
      toggleTabHandler(this);
      super.dispose(tabComponent);
    }
  }

  Tab.init = {
    component: tabComponent,
    selector: tabSelector,
    constructor: Tab,
  };

  /* Native JavaScript for Bootstrap 5 | Toast
  -------------------------------------------- */

  // TOAST PRIVATE GC
  // ================
  const toastString = 'toast';
  const toastComponent = 'Toast';
  const toastSelector = `.${toastString}`;
  const toastDismissSelector = `[${dataBsDismiss}="${toastString}"]`;
  const showingClass = 'showing';
  const hideClass = 'hide';
  const toastDefaultOptions = {
    animation: true,
    autohide: true,
    delay: 500,
  };

  // TOAST CUSTOM EVENTS
  // ===================
  const showToastEvent = bootstrapCustomEvent(`show.bs.${toastString}`);
  const hideToastEvent = bootstrapCustomEvent(`hide.bs.${toastString}`);
  const shownToastEvent = bootstrapCustomEvent(`shown.bs.${toastString}`);
  const hiddenToastEvent = bootstrapCustomEvent(`hidden.bs.${toastString}`);

  // TOAST PRIVATE METHODS
  // =====================
  function showToastComplete(self) {
    const { element, options } = self;
    if (!options.animation) {
      removeClass(element, showingClass);
      addClass(element, showClass);
    }

    element.dispatchEvent(shownToastEvent);
    if (options.autohide) self.hide();
  }

  function hideToastComplete(self) {
    const { element } = self;
    addClass(element, hideClass);
    element.dispatchEvent(hiddenToastEvent);
  }

  function closeToast(self) {
    const { element, options } = self;
    removeClass(element, showClass);

    if (options.animation) {
      reflow(element);
      emulateTransitionEnd(element, () => hideToastComplete(self));
    } else {
      hideToastComplete(self);
    }
  }

  function openToast(self) {
    const { element, options } = self;
    removeClass(element, hideClass);

    if (options.animation) {
      reflow(element);
      addClass(element, showingClass);
      addClass(element, showClass);

      emulateTransitionEnd(element, () => showToastComplete(self));
    } else {
      showToastComplete(self);
    }
  }

  function toggleToastHandler(self, add) {
    const action = add ? addEventListener : removeEventListener;
    if (self.dismiss) {
      self.dismiss[action]('click', self.hide);
    }
  }

  // TOAST EVENT HANDLERS
  // ====================
  function completeDisposeToast(self) {
    clearTimeout(self.timer);
    toggleToastHandler(self);
  }

  // TOAST DEFINITION
  // ================
  class Toast extends BaseComponent {
    constructor(target, config) {
      super(toastComponent, target, toastDefaultOptions, config);
      // bind
      const self = this;

      // dismiss button
      self.dismiss = queryElement(toastDismissSelector, self.element);

      // bind
      self.show = self.show.bind(self);
      self.hide = self.hide.bind(self);

      // add event listener
      toggleToastHandler(self, 1);
    }

    // TOAST PUBLIC METHODS
    // ====================
    show() {
      const self = this;
      const { element } = self;
      if (element && hasClass(element, hideClass)) {
        element.dispatchEvent(showToastEvent);
        if (showToastEvent.defaultPrevented) return;

        addClass(element, fadeClass);
        clearTimeout(self.timer);
        self.timer = setTimeout(() => openToast(self), 10);
      }
    }

    hide(noTimer) {
      const self = this;
      const { element, options } = self;

      if (element && hasClass(element, showClass)) {
        element.dispatchEvent(hideToastEvent);
        if (hideToastEvent.defaultPrevented) return;

        clearTimeout(self.timer);
        self.timer = setTimeout(() => closeToast(self),
          noTimer ? 10 : options.delay);
      }
    }

    dispose() {
      const self = this;
      const { element, options } = self;
      self.hide();

      if (options.animation) emulateTransitionEnd(element, () => completeDisposeToast(self));
      else completeDisposeToast(self);

      super.dispose(toastComponent);
    }
  }

  Toast.init = {
    component: toastComponent,
    selector: toastSelector,
    constructor: Toast,
  };

  const dataOriginalTitle = 'data-original-title';

  /* Native JavaScript for Bootstrap 5 | Tooltip
  ---------------------------------------------- */

  // TOOLTIP PRIVATE GC
  // ==================
  const tooltipString = 'tooltip';
  const tooltipComponent = 'Tooltip';
  const tooltipSelector = `[${dataBsToggle}="${tooltipString}"],[data-tip="${tooltipString}"]`;

  const titleAttr = 'title';
  const tooltipInnerClass = `${tooltipString}-inner`;
  const tooltipDefaultOptions = {
    title: null,
    template: '<div class="tooltip" role="tooltip"><div class="tooltip-arrow"></div><div class="tooltip-inner"></div></div>',
    placement: 'top',
    animation: true,
    customClass: null,
    delay: 200,
    sanitizeFn: null,
  };

  // TOOLTIP CUSTOM EVENTS
  // =====================
  const showTooltipEvent = bootstrapCustomEvent(`show.bs.${tooltipString}`);
  const shownTooltipEvent = bootstrapCustomEvent(`shown.bs.${tooltipString}`);
  const hideTooltipEvent = bootstrapCustomEvent(`hide.bs.${tooltipString}`);
  const hiddenTooltipEvent = bootstrapCustomEvent(`hidden.bs.${tooltipString}`);

  // TOOLTIP PRIVATE METHODS
  // =======================
  function createTooltip(self) {
    const { options, id } = self;
    const placementClass = `bs-${tooltipString}-${tipClassPositions[options.placement]}`;
    let titleString = options.title.trim();

    // sanitize stuff
    if (options.sanitizeFn) {
      titleString = options.sanitizeFn(titleString);
      options.template = options.sanitizeFn(options.template);
    }

    if (!titleString) return;

    // create tooltip
    self.tooltip = document.createElement('div');
    const { tooltip } = self;

    // set aria
    tooltip.setAttribute('id', id);

    // set markup
    const tooltipMarkup = document.createElement('div');
    tooltipMarkup.innerHTML = options.template.trim();

    tooltip.className = tooltipMarkup.firstChild.className;
    tooltip.innerHTML = tooltipMarkup.firstChild.innerHTML;

    queryElement(`.${tooltipInnerClass}`, tooltip).innerHTML = titleString;

    // set arrow
    self.arrow = queryElement(`.${tooltipString}-arrow`, tooltip);

    // set class and role attribute
    tooltip.setAttribute('role', tooltipString);
    // set classes
    if (!hasClass(tooltip, tooltipString)) addClass(tooltip, tooltipString);
    if (options.animation && !hasClass(tooltip, fadeClass)) addClass(tooltip, fadeClass);
    if (options.customClass && !hasClass(tooltip, options.customClass)) {
      addClass(tooltip, options.customClass);
    }
    if (!hasClass(tooltip, placementClass)) addClass(tooltip, placementClass);
  }

  function removeTooltip(self) {
    const { element, options, tooltip } = self;
    element.removeAttribute(ariaDescribedBy);
    options.container.removeChild(tooltip);
    self.timer = null;
  }

  function disposeTooltipComplete(self) {
    const { element } = self;
    toggleTooltipHandlers(self);
    if (element.hasAttribute(dataOriginalTitle)) toggleTooltipTitle(self);
  }
  function toggleTooltipAction(self, add) {
    const action = add ? addEventListener : removeEventListener;

    document[action]('touchstart', tooltipTouchHandler, passiveHandler);

    if (!isMedia(self.element)) {
      window[action]('scroll', self.update, passiveHandler);
      window[action]('resize', self.update, passiveHandler);
    }
  }
  function tooltipShownAction(self) {
    toggleTooltipAction(self, 1);
    self.element.dispatchEvent(shownTooltipEvent);
  }
  function tooltipHiddenAction(self) {
    toggleTooltipAction(self);
    removeTooltip(self);
    self.element.dispatchEvent(hiddenTooltipEvent);
  }
  function toggleTooltipHandlers(self, add) {
    const action = add ? addEventListener : removeEventListener;
    const { element } = self;

    if (isMedia(element)) element[action]('mousemove', self.update, passiveHandler);
    element[action]('mousedown', self.show);
    element[action]('mouseenter', self.show);
    element[action]('mouseleave', self.hide);
  }

  function toggleTooltipTitle(self, content) {
    // [0 - add, 1 - remove] | [0 - remove, 1 - add]
    const titleAtt = [dataOriginalTitle, titleAttr];
    const { element } = self;

    element.setAttribute(titleAtt[content ? 0 : 1],
      (content || element.getAttribute(titleAtt[0])));
    element.removeAttribute(titleAtt[content ? 1 : 0]);
  }

  // TOOLTIP EVENT HANDLERS
  // ======================
  function tooltipTouchHandler({ target }) {
    const { tooltip, element } = this;
    if (tooltip.contains(target) || target === element || element.contains(target)) ; else {
      this.hide();
    }
  }

  // TOOLTIP DEFINITION
  // ==================
  class Tooltip extends BaseComponent {
    constructor(target, config) {
      // initialization element
      const element = queryElement(target);
      tooltipDefaultOptions.title = element.getAttribute(titleAttr);
      tooltipDefaultOptions.container = getTipContainer(element);
      super(tooltipComponent, element, tooltipDefaultOptions, config);

      // bind
      const self = this;

      // additional properties
      self.tooltip = null;
      self.arrow = null;
      self.timer = null;
      self.enabled = false;

      // instance options
      const { options } = self;

      // media elements only work with body as a container
      self.options.container = isMedia(element)
        ? tooltipDefaultOptions.container
        : queryElement(options.container);

      // reset default options
      tooltipDefaultOptions.container = null;
      tooltipDefaultOptions[titleAttr] = null;

      // invalidate
      if (!options.title) return;

      // all functions bind
      tooltipTouchHandler.bind(self);
      self.update = self.update.bind(self);

      // set title attributes and add event listeners
      if (element.hasAttribute(titleAttr)) toggleTooltipTitle(self, options.title);

      // create tooltip here
      self.id = `${tooltipString}-${getUID(element)}`;
      createTooltip(self);

      // attach events
      toggleTooltipHandlers(self, 1);
    }

    // TOOLTIP PUBLIC METHODS
    // ======================
    show(e) {
      const self = e ? this[tooltipComponent] : this;
      const {
        options, tooltip, element, id,
      } = self;
      clearTimeout(self.timer);
      self.timer = setTimeout(() => {
        if (!isVisibleTip(tooltip, options.container)) {
          element.dispatchEvent(showTooltipEvent);
          if (showTooltipEvent.defaultPrevented) return;

          // append to container
          options.container.appendChild(tooltip);
          element.setAttribute(ariaDescribedBy, id);

          self.update(e);
          if (!hasClass(tooltip, showClass)) addClass(tooltip, showClass);
          if (options.animation) emulateTransitionEnd(tooltip, () => tooltipShownAction(self));
          else tooltipShownAction(self);
        }
      }, 20);
    }

    hide(e) {
      const self = e ? this[tooltipComponent] : this;
      const { options, tooltip, element } = self;

      clearTimeout(self.timer);
      self.timer = setTimeout(() => {
        if (isVisibleTip(tooltip, options.container)) {
          element.dispatchEvent(hideTooltipEvent);
          if (hideTooltipEvent.defaultPrevented) return;

          removeClass(tooltip, showClass);
          if (options.animation) emulateTransitionEnd(tooltip, () => tooltipHiddenAction(self));
          else tooltipHiddenAction(self);
        }
      }, options.delay);
    }

    update(e) {
      styleTip(this, e);
    }

    toggle() {
      const self = this;
      const { tooltip, options } = self;
      if (!isVisibleTip(tooltip, options.container)) self.show();
      else self.hide();
    }

    enable() {
      const self = this;
      const { enabled } = self;
      if (!enabled) {
        toggleTooltipHandlers(self, 1);
        self.enabled = !enabled;
      }
    }

    disable() {
      const self = this;
      const { tooltip, options, enabled } = self;
      if (enabled) {
        if (!isVisibleTip(tooltip, options.container) && options.animation) {
          self.hide();

          setTimeout(
            () => toggleTooltipHandlers(self),
            getElementTransitionDuration(tooltip) + options.delay + 17,
          );
        } else {
          toggleTooltipHandlers(self);
        }
        self.enabled = !enabled;
      }
    }

    toggleEnabled() {
      const self = this;
      if (!self.enabled) self.enable();
      else self.disable();
    }

    dispose() {
      const self = this;
      const { tooltip, options } = self;

      if (options.animation && isVisibleTip(tooltip, options.container)) {
        options.delay = 0; // reset delay
        self.hide();
        emulateTransitionEnd(tooltip, () => disposeTooltipComplete(self));
      } else {
        disposeTooltipComplete(self);
      }
      super.dispose(tooltipComponent);
    }
  }

  Tooltip.init = {
    component: tooltipComponent,
    selector: tooltipSelector,
    constructor: Tooltip,
  };

  var version = "4.0.4";

  // import { alertInit } from '../components/alert-native.js';
  // import { buttonInit } from '../components/button-native.js';
  // import { carouselInit } from '../components/carousel-native.js';
  // import { collapseInit } from '../components/collapse-native.js';
  // import { dropdownInit } from '../components/dropdown-native.js';
  // import { modalInit } from '../components/modal-native.js';
  // import { offcanvasInit } from '../components/offcanvas-native.js';
  // import { popoverInit } from '../components/popover-native.js';
  // import { scrollSpyInit } from '../components/scrollspy-native.js';
  // import { tabInit } from '../components/tab-native.js';
  // import { toastInit } from '../components/toast-native.js';
  // import { tooltipInit } from '../components/tooltip-native.js';

  const componentsInit = {
    Alert: Alert.init,
    Button: Button.init,
    Carousel: Carousel.init,
    Collapse: Collapse.init,
    Dropdown: Dropdown.init,
    Modal: Modal.init,
    Offcanvas: Offcanvas.init,
    Popover: Popover.init,
    ScrollSpy: ScrollSpy.init,
    Tab: Tab.init,
    Toast: Toast.init,
    Tooltip: Tooltip.init,
  };

  function initializeDataAPI(Konstructor, collection) {
    Array.from(collection).forEach((x) => new Konstructor(x));
  }

  function initCallback(context) {
    const lookUp = context instanceof Element ? context : document;

    Object.keys(componentsInit).forEach((comp) => {
      const { constructor, selector } = componentsInit[comp];
      initializeDataAPI(constructor, lookUp.querySelectorAll(selector));
    });
  }

  // bulk initialize all components
  if (document.body) initCallback();
  else {
    document.addEventListener('DOMContentLoaded', () => initCallback(), { once: true });
  }

  var index = {
    Alert,
    Button,
    Carousel,
    Collapse,
    Dropdown,
    Modal,
    Offcanvas,
    Popover,
    ScrollSpy,
    Tab,
    Toast,
    Tooltip,

    initCallback,
    Version: version,
  };

  return index;

})));
