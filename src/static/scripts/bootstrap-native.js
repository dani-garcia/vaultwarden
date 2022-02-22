/*!
  * Native JavaScript for Bootstrap v4.1.0 (https://thednp.github.io/bootstrap.native/)
  * Copyright 2015-2022 © dnp_theme
  * Licensed under MIT (https://github.com/thednp/bootstrap.native/blob/master/LICENSE)
  */
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.BSN = factory());
})(this, (function () { 'use strict';

  /** @type {Record<string, any>} */
  const EventRegistry = {};

  /**
   * The global event listener.
   *
   * @this {Element | HTMLElement | Window | Document}
   * @param {Event} e
   * @returns {void}
   */
  function globalListener(e) {
    const that = this;
    const { type } = e;
    const oneEvMap = EventRegistry[type] ? [...EventRegistry[type]] : [];

    oneEvMap.forEach((elementsMap) => {
      const [element, listenersMap] = elementsMap;
      [...listenersMap].forEach((listenerMap) => {
        if (element === that) {
          const [listener, options] = listenerMap;
          listener.apply(element, [e]);

          if (options && options.once) {
            removeListener(element, type, listener, options);
          }
        }
      });
    });
  }

  /**
   * Register a new listener with its options and attach the `globalListener`
   * to the target if this is the first listener.
   *
   * @param {Element | HTMLElement | Window | Document} element
   * @param {string} eventType
   * @param {EventListenerObject['handleEvent']} listener
   * @param {AddEventListenerOptions=} options
   */
  const addListener = (element, eventType, listener, options) => {
    // get element listeners first
    if (!EventRegistry[eventType]) {
      EventRegistry[eventType] = new Map();
    }
    const oneEventMap = EventRegistry[eventType];

    if (!oneEventMap.has(element)) {
      oneEventMap.set(element, new Map());
    }
    const oneElementMap = oneEventMap.get(element);

    // get listeners size
    const { size } = oneElementMap;

    // register listener with its options
    if (oneElementMap) {
      oneElementMap.set(listener, options);
    }

    // add listener last
    if (!size) {
      element.addEventListener(eventType, globalListener, options);
    }
  };

  /**
   * Remove a listener from registry and detach the `globalListener`
   * if no listeners are found in the registry.
   *
   * @param {Element | HTMLElement | Window | Document} element
   * @param {string} eventType
   * @param {EventListenerObject['handleEvent']} listener
   * @param {AddEventListenerOptions=} options
   */
  const removeListener = (element, eventType, listener, options) => {
    // get listener first
    const oneEventMap = EventRegistry[eventType];
    const oneElementMap = oneEventMap && oneEventMap.get(element);
    const savedOptions = oneElementMap && oneElementMap.get(listener);

    // also recover initial options
    const { options: eventOptions } = savedOptions !== undefined
      ? savedOptions
      : { options };

    // unsubscribe second, remove from registry
    if (oneElementMap && oneElementMap.has(listener)) oneElementMap.delete(listener);
    if (oneEventMap && (!oneElementMap || !oneElementMap.size)) oneEventMap.delete(element);
    if (!oneEventMap || !oneEventMap.size) delete EventRegistry[eventType];

    // remove listener last
    if (!oneElementMap || !oneElementMap.size) {
      element.removeEventListener(eventType, globalListener, eventOptions);
    }
  };

  /**
   * Advanced event listener based on subscribe / publish pattern.
   * @see https://www.patterns.dev/posts/classic-design-patterns/#observerpatternjavascript
   * @see https://gist.github.com/shystruk/d16c0ee7ac7d194da9644e5d740c8338#file-subpub-js
   * @see https://hackernoon.com/do-you-still-register-window-event-listeners-in-each-component-react-in-example-31a4b1f6f1c8
   */
  const EventListener = {
    on: addListener,
    off: removeListener,
    globalListener,
    registry: EventRegistry,
  };

  /**
   * A global namespace for `click` event.
   * @type {string}
   */
  const mouseclickEvent = 'click';

  /**
   * A global namespace for 'transitionend' string.
   * @type {string}
   */
  const transitionEndEvent = 'transitionend';

  /**
   * A global namespace for 'transitionDelay' string.
   * @type {string}
   */
  const transitionDelay = 'transitionDelay';

  /**
   * A global namespace for `transitionProperty` string for modern browsers.
   *
   * @type {string}
   */
  const transitionProperty = 'transitionProperty';

  /**
   * Shortcut for `window.getComputedStyle(element).propertyName`
   * static method.
   *
   * * If `element` parameter is not an `HTMLElement`, `getComputedStyle`
   * throws a `ReferenceError`.
   *
   * @param {HTMLElement | Element} element target
   * @param {string} property the css property
   * @return {string} the css property value
   */
  function getElementStyle(element, property) {
    const computedStyle = getComputedStyle(element);

    // @ts-ignore -- must use camelcase strings,
    // or non-camelcase strings with `getPropertyValue`
    return property in computedStyle ? computedStyle[property] : '';
  }

  /**
   * Utility to get the computed `transitionDelay`
   * from Element in miliseconds.
   *
   * @param {HTMLElement | Element} element target
   * @return {number} the value in miliseconds
   */
  function getElementTransitionDelay(element) {
    const propertyValue = getElementStyle(element, transitionProperty);
    const delayValue = getElementStyle(element, transitionDelay);

    const delayScale = delayValue.includes('ms') ? 1 : 1000;
    const duration = propertyValue && propertyValue !== 'none'
      ? parseFloat(delayValue) * delayScale : 0;

    return !Number.isNaN(duration) ? duration : 0;
  }

  /**
   * A global namespace for 'transitionDuration' string.
   * @type {string}
   */
  const transitionDuration = 'transitionDuration';

  /**
   * Utility to get the computed `transitionDuration`
   * from Element in miliseconds.
   *
   * @param {HTMLElement | Element} element target
   * @return {number} the value in miliseconds
   */
  function getElementTransitionDuration(element) {
    const propertyValue = getElementStyle(element, transitionProperty);
    const durationValue = getElementStyle(element, transitionDuration);
    const durationScale = durationValue.includes('ms') ? 1 : 1000;
    const duration = propertyValue && propertyValue !== 'none'
      ? parseFloat(durationValue) * durationScale : 0;

    return !Number.isNaN(duration) ? duration : 0;
  }

  /**
   * Utility to make sure callbacks are consistently
   * called when transition ends.
   *
   * @param {HTMLElement | Element} element target
   * @param {EventListener} handler `transitionend` callback
   */
  function emulateTransitionEnd(element, handler) {
    let called = 0;
    const endEvent = new Event(transitionEndEvent);
    const duration = getElementTransitionDuration(element);
    const delay = getElementTransitionDelay(element);

    if (duration) {
      /**
       * Wrap the handler in on -> off callback
       * @type {EventListener} e Event object
       */
      const transitionEndWrapper = (e) => {
        if (e.target === element) {
          handler.apply(element, [e]);
          element.removeEventListener(transitionEndEvent, transitionEndWrapper);
          called = 1;
        }
      };
      element.addEventListener(transitionEndEvent, transitionEndWrapper);
      setTimeout(() => {
        if (!called) element.dispatchEvent(endEvent);
      }, duration + delay + 17);
    } else {
      handler.apply(element, [endEvent]);
    }
  }

  /**
   * Returns the `document` or the `#document` element.
   * @see https://github.com/floating-ui/floating-ui
   * @param {(Node | HTMLElement | Element | globalThis)=} node
   * @returns {Document}
   */
  function getDocument(node) {
    if (node instanceof HTMLElement) return node.ownerDocument;
    if (node instanceof Window) return node.document;
    return window.document;
  }

  /**
   * A global array of possible `ParentNode`.
   */
  const parentNodes = [Document, Element, HTMLElement];

  /**
   * A global array with `Element` | `HTMLElement`.
   */
  const elementNodes = [Element, HTMLElement];

  /**
   * Utility to check if target is typeof `HTMLElement`, `Element`, `Node`
   * or find one that matches a selector.
   *
   * @param {HTMLElement | Element | string} selector the input selector or target element
   * @param {(HTMLElement | Element | Document)=} parent optional node to look into
   * @return {(HTMLElement | Element)?} the `HTMLElement` or `querySelector` result
   */
  function querySelector(selector, parent) {
    const lookUp = parentNodes.some((x) => parent instanceof x)
      ? parent : getDocument();

    // @ts-ignore
    return elementNodes.some((x) => selector instanceof x)
      // @ts-ignore
      ? selector : lookUp.querySelector(selector);
  }

  /**
   * Shortcut for `HTMLElement.closest` method which also works
   * with children of `ShadowRoot`. The order of the parameters
   * is intentional since they're both required.
   *
   * @see https://stackoverflow.com/q/54520554/803358
   *
   * @param {HTMLElement | Element} element Element to look into
   * @param {string} selector the selector name
   * @return {(HTMLElement | Element)?} the query result
   */
  function closest(element, selector) {
    return element ? (element.closest(selector)
      // @ts-ignore -- break out of `ShadowRoot`
      || closest(element.getRootNode().host, selector)) : null;
  }

  /**
   * Shortcut for `Object.assign()` static method.
   * @param  {Record<string, any>} obj a target object
   * @param  {Record<string, any>} source a source object
   */
  const ObjectAssign = (obj, source) => Object.assign(obj, source);

  /**
   * Check class in `HTMLElement.classList`.
   *
   * @param {HTMLElement | Element} element target
   * @param {string} classNAME to check
   * @returns {boolean}
   */
  function hasClass(element, classNAME) {
    return element.classList.contains(classNAME);
  }

  /**
   * Remove class from `HTMLElement.classList`.
   *
   * @param {HTMLElement | Element} element target
   * @param {string} classNAME to remove
   * @returns {void}
   */
  function removeClass(element, classNAME) {
    element.classList.remove(classNAME);
  }

  /**
   * Shortcut for the `Element.dispatchEvent(Event)` method.
   *
   * @param {HTMLElement | Element} element is the target
   * @param {Event} event is the `Event` object
   */
  const dispatchEvent = (element, event) => element.dispatchEvent(event);

  /** @type {Map<string, Map<HTMLElement | Element, Record<string, any>>>} */
  const componentData = new Map();
  /**
   * An interface for web components background data.
   * @see https://github.com/thednp/bootstrap.native/blob/master/src/components/base-component.js
   */
  const Data = {
    /**
     * Sets web components data.
     * @param {HTMLElement | Element | string} target target element
     * @param {string} component the component's name or a unique key
     * @param {Record<string, any>} instance the component instance
     */
    set: (target, component, instance) => {
      const element = querySelector(target);
      if (!element) return;

      if (!componentData.has(component)) {
        componentData.set(component, new Map());
      }

      const instanceMap = componentData.get(component);
      // @ts-ignore - not undefined, but defined right above
      instanceMap.set(element, instance);
    },

    /**
     * Returns all instances for specified component.
     * @param {string} component the component's name or a unique key
     * @returns {Map<HTMLElement | Element, Record<string, any>>?} all the component instances
     */
    getAllFor: (component) => {
      const instanceMap = componentData.get(component);

      return instanceMap || null;
    },

    /**
     * Returns the instance associated with the target.
     * @param {HTMLElement | Element | string} target target element
     * @param {string} component the component's name or a unique key
     * @returns {Record<string, any>?} the instance
     */
    get: (target, component) => {
      const element = querySelector(target);
      const allForC = Data.getAllFor(component);
      const instance = element && allForC && allForC.get(element);

      return instance || null;
    },

    /**
     * Removes web components data.
     * @param {HTMLElement | Element | string} target target element
     * @param {string} component the component's name or a unique key
     */
    remove: (target, component) => {
      const element = querySelector(target);
      const instanceMap = componentData.get(component);
      if (!instanceMap || !element) return;

      instanceMap.delete(element);

      if (instanceMap.size === 0) {
        componentData.delete(component);
      }
    },
  };

  /**
   * An alias for `Data.get()`.
   * @type {SHORTER.getInstance<any>}
   */
  const getInstance = (target, component) => Data.get(target, component);

  /**
   * Returns a namespaced `CustomEvent` specific to each component.
   * @param {string} EventType Event.type
   * @param {Record<string, any>=} config Event.options | Event.properties
   * @returns {SHORTER.OriginalEvent} a new namespaced event
   */
  function OriginalEvent(EventType, config) {
    const OriginalCustomEvent = new CustomEvent(EventType, {
      cancelable: true, bubbles: true,
    });

    if (config instanceof Object) {
      ObjectAssign(OriginalCustomEvent, config);
    }
    return OriginalCustomEvent;
  }

  /**
   * Global namespace for most components `fade` class.
   */
  const fadeClass = 'fade';

  /**
   * Global namespace for most components `show` class.
   */
  const showClass = 'show';

  /**
   * Global namespace for most components `dismiss` option.
   */
  const dataBsDismiss = 'data-bs-dismiss';

  /** @type {string} */
  const alertString = 'alert';

  /** @type {string} */
  const alertComponent = 'Alert';

  /**
   * Shortcut for `HTMLElement.getAttribute()` method.
   * @param {HTMLElement | Element} element target element
   * @param {string} attribute attribute name
   * @returns {string?} attribute value
   */
  const getAttribute = (element, attribute) => element.getAttribute(attribute);

  /**
   * The raw value or a given component option.
   *
   * @typedef {string | HTMLElement | Function | number | boolean | null} niceValue
   */

  /**
   * Utility to normalize component options
   *
   * @param {any} value the input value
   * @return {niceValue} the normalized value
   */
  function normalizeValue(value) {
    if (value === 'true') { // boolean
      return true;
    }

    if (value === 'false') { // boolean
      return false;
    }

    if (!Number.isNaN(+value)) { // number
      return +value;
    }

    if (value === '' || value === 'null') { // null
      return null;
    }

    // string / function / HTMLElement / object
    return value;
  }

  /**
   * Shortcut for `Object.keys()` static method.
   * @param  {Record<string, any>} obj a target object
   * @returns {string[]}
   */
  const ObjectKeys = (obj) => Object.keys(obj);

  /**
   * Shortcut for `String.toLowerCase()`.
   *
   * @param {string} source input string
   * @returns {string} lowercase output string
   */
  const toLowerCase = (source) => source.toLowerCase();

  /**
   * Utility to normalize component options.
   *
   * @param {HTMLElement | Element} element target
   * @param {Record<string, any>} defaultOps component default options
   * @param {Record<string, any>} inputOps component instance options
   * @param {string=} ns component namespace
   * @return {Record<string, any>} normalized component options object
   */
  function normalizeOptions(element, defaultOps, inputOps, ns) {
    // @ts-ignore -- our targets are always `HTMLElement`
    const data = { ...element.dataset };
    /** @type {Record<string, any>} */
    const normalOps = {};
    /** @type {Record<string, any>} */
    const dataOps = {};
    const title = 'title';

    ObjectKeys(data).forEach((k) => {
      const key = ns && k.includes(ns)
        ? k.replace(ns, '').replace(/[A-Z]/, (match) => toLowerCase(match))
        : k;

      dataOps[key] = normalizeValue(data[k]);
    });

    ObjectKeys(inputOps).forEach((k) => {
      inputOps[k] = normalizeValue(inputOps[k]);
    });

    ObjectKeys(defaultOps).forEach((k) => {
      if (k in inputOps) {
        normalOps[k] = inputOps[k];
      } else if (k in dataOps) {
        normalOps[k] = dataOps[k];
      } else {
        normalOps[k] = k === title
          ? getAttribute(element, title)
          : defaultOps[k];
      }
    });

    return normalOps;
  }

  var version = "4.1.0";

  const Version = version;

  /* Native JavaScript for Bootstrap 5 | Base Component
  ----------------------------------------------------- */

  /** Returns a new `BaseComponent` instance. */
  class BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target `Element` or selector string
     * @param {BSN.ComponentOptions=} config component instance options
     */
    constructor(target, config) {
      const self = this;
      const element = querySelector(target);

      if (!element) {
        throw Error(`${self.name} Error: "${target}" is not a valid selector.`);
      }

      /** @static @type {BSN.ComponentOptions} */
      self.options = {};

      const prevInstance = Data.get(element, self.name);
      if (prevInstance) prevInstance.dispose();

      /** @type {HTMLElement | Element} */
      self.element = element;

      if (self.defaults && Object.keys(self.defaults).length) {
        self.options = normalizeOptions(element, self.defaults, (config || {}), 'bs');
      }

      Data.set(element, self.name, self);
    }

    /* eslint-disable */
    /** @static */
    get version() { return Version; }
    /* eslint-enable */

    /** @static */
    get name() { return this.constructor.name; }

    /** @static */
    // @ts-ignore
    get defaults() { return this.constructor.defaults; }

    /**
     * Removes component from target element;
     */
    dispose() {
      const self = this;
      Data.remove(self.element, self.name);
      // @ts-ignore
      ObjectKeys(self).forEach((prop) => { self[prop] = null; });
    }
  }

  /* Native JavaScript for Bootstrap 5 | Alert
  -------------------------------------------- */

  // ALERT PRIVATE GC
  // ================
  const alertSelector = `.${alertString}`;
  const alertDismissSelector = `[${dataBsDismiss}="${alertString}"]`;

  /**
   * Static method which returns an existing `Alert` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Alert>}
   */
  const getAlertInstance = (element) => getInstance(element, alertComponent);

  /**
  * An `Alert` initialization callback.
  * @type {BSN.InitCallback<Alert>}
  */
  const alertInitCallback = (element) => new Alert(element);

  // ALERT CUSTOM EVENTS
  // ===================
  const closeAlertEvent = OriginalEvent(`close.bs.${alertString}`);
  const closedAlertEvent = OriginalEvent(`closed.bs.${alertString}`);

  // ALERT EVENT HANDLER
  // ===================
  /**
   * Alert `transitionend` callback.
   * @param {Alert} self target Alert instance
   */
  function alertTransitionEnd(self) {
    const { element } = self;
    toggleAlertHandler(self);

    dispatchEvent(element, closedAlertEvent);

    self.dispose();
    element.remove();
  }

  // ALERT PRIVATE METHOD
  // ====================
  /**
   * Toggle on / off the `click` event listener.
   * @param {Alert} self the target alert instance
   * @param {boolean=} add when `true`, event listener is added
   */
  function toggleAlertHandler(self, add) {
    const action = add ? addListener : removeListener;
    const { dismiss } = self;
    if (dismiss) action(dismiss, mouseclickEvent, self.close);
  }

  // ALERT DEFINITION
  // ================
  /** Creates a new Alert instance. */
  class Alert extends BaseComponent {
    /** @param {HTMLElement | Element | string} target element or selector */
    constructor(target) {
      super(target);
      // bind
      const self = this;

      // initialization element
      const { element } = self;

      // the dismiss button
      /** @static @type {(HTMLElement | Element)?} */
      self.dismiss = querySelector(alertDismissSelector, element);

      // add event listener
      toggleAlertHandler(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return alertComponent; }
    /* eslint-enable */

    // ALERT PUBLIC METHODS
    // ====================
    /**
     * Public method that hides the `.alert` element from the user,
     * disposes the instance once animation is complete, then
     * removes the element from the DOM.
     *
     * @param {Event=} e most likely the `click` event
     * @this {Alert} the `Alert` instance or `EventTarget`
     */
    close(e) {
      // @ts-ignore
      const self = e ? getAlertInstance(closest(this, alertSelector)) : this;
      if (!self) return;
      const { element } = self;

      if (hasClass(element, showClass)) {
        dispatchEvent(element, closeAlertEvent);
        if (closeAlertEvent.defaultPrevented) return;

        removeClass(element, showClass);

        if (hasClass(element, fadeClass)) {
          emulateTransitionEnd(element, () => alertTransitionEnd(self));
        } else alertTransitionEnd(self);
      }
    }

    /** Remove the component from target element. */
    dispose() {
      toggleAlertHandler(this);
      super.dispose();
    }
  }

  ObjectAssign(Alert, {
    selector: alertSelector,
    init: alertInitCallback,
    getInstance: getAlertInstance,
  });

  /**
   * A global namespace for aria-pressed.
   * @type {string}
   */
  const ariaPressed = 'aria-pressed';

  /**
   * Shortcut for `HTMLElement.setAttribute()` method.
   * @param  {HTMLElement | Element} element target element
   * @param  {string} attribute attribute name
   * @param  {string} value attribute value
   * @returns {void}
   */
  const setAttribute = (element, attribute, value) => element.setAttribute(attribute, value);

  /**
   * Add class to `HTMLElement.classList`.
   *
   * @param {HTMLElement | Element} element target
   * @param {string} classNAME to add
   * @returns {void}
   */
  function addClass(element, classNAME) {
    element.classList.add(classNAME);
  }

  /**
   * Global namespace for most components active class.
   */
  const activeClass = 'active';

  /**
   * Global namespace for most components `toggle` option.
   */
  const dataBsToggle = 'data-bs-toggle';

  /** @type {string} */
  const buttonString = 'button';

  /** @type {string} */
  const buttonComponent = 'Button';

  /* Native JavaScript for Bootstrap 5 | Button
  ---------------------------------------------*/

  // BUTTON PRIVATE GC
  // =================
  const buttonSelector = `[${dataBsToggle}="${buttonString}"]`;

  /**
   * Static method which returns an existing `Button` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Button>}
   */
  const getButtonInstance = (element) => getInstance(element, buttonComponent);

  /**
   * A `Button` initialization callback.
   * @type {BSN.InitCallback<Button>}
   */
  const buttonInitCallback = (element) => new Button(element);

  // BUTTON PRIVATE METHOD
  // =====================
  /**
   * Toggles on/off the `click` event listener.
   * @param {Button} self the `Button` instance
   * @param {boolean=} add when `true`, event listener is added
   */
  function toggleButtonHandler(self, add) {
    const action = add ? addListener : removeListener;
    action(self.element, mouseclickEvent, self.toggle);
  }

  // BUTTON DEFINITION
  // =================
  /** Creates a new `Button` instance. */
  class Button extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target usually a `.btn` element
     */
    constructor(target) {
      super(target);
      const self = this;

      // initialization element
      const { element } = self;

      // set initial state
      /** @type {boolean} */
      self.isActive = hasClass(element, activeClass);
      setAttribute(element, ariaPressed, `${!!self.isActive}`);

      // add event listener
      toggleButtonHandler(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return buttonComponent; }
    /* eslint-enable */

    // BUTTON PUBLIC METHODS
    // =====================
    /**
     * Toggles the state of the target button.
     * @param {MouseEvent} e usually `click` Event object
     */
    toggle(e) {
      if (e) e.preventDefault();
      // @ts-ignore
      const self = e ? getButtonInstance(this) : this;
      if (!self) return;
      const { element } = self;

      if (hasClass(element, 'disabled')) return;
      self.isActive = hasClass(element, activeClass);
      const { isActive } = self;

      const action = isActive ? removeClass : addClass;

      action(element, activeClass);
      setAttribute(element, ariaPressed, isActive ? 'false' : 'true');
    }

    /** Removes the `Button` component from the target element. */
    dispose() {
      toggleButtonHandler(this);
      super.dispose();
    }
  }

  ObjectAssign(Button, {
    selector: buttonSelector,
    init: buttonInitCallback,
    getInstance: getButtonInstance,
  });

  /**
   * A global namespace for `mouseenter` event.
   * @type {string}
   */
  const mouseenterEvent = 'mouseenter';

  /**
   * A global namespace for `mouseleave` event.
   * @type {string}
   */
  const mouseleaveEvent = 'mouseleave';

  /**
   * A global namespace for `keydown` event.
   * @type {string}
   */
  const keydownEvent = 'keydown';

  /**
   * A global namespace for `touchmove` event.
   * @type {string}
   */
  const touchmoveEvent = 'touchmove';

  /**
   * A global namespace for `touchend` event.
   * @type {string}
   */
  const touchendEvent = 'touchend';

  /**
   * A global namespace for `touchstart` event.
   * @type {string}
   */
  const touchstartEvent = 'touchstart';

  /**
   * A global namespace for `ArrowLeft` key.
   * @type {string} e.which = 37 equivalent
   */
  const keyArrowLeft = 'ArrowLeft';

  /**
   * A global namespace for `ArrowRight` key.
   * @type {string} e.which = 39 equivalent
   */
  const keyArrowRight = 'ArrowRight';

  /**
   * Returns the `Window` object of a target node.
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {(Node | HTMLElement | Element | Window)=} node target node
   * @returns {globalThis}
   */
  function getWindow(node) {
    if (node == null) {
      return window;
    }

    if (!(node instanceof Window)) {
      const { ownerDocument } = node;
      return ownerDocument ? ownerDocument.defaultView || window : window;
    }

    // @ts-ignore
    return node;
  }

  /**
   * Returns the bounding client rect of a target `HTMLElement`.
   *
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {HTMLElement | Element} element event.target
   * @param {boolean=} includeScale when *true*, the target scale is also computed
   * @returns {SHORTER.BoundingClientRect} the bounding client rect object
   */
  function getBoundingClientRect(element, includeScale) {
    const {
      width, height, top, right, bottom, left,
    } = element.getBoundingClientRect();
    let scaleX = 1;
    let scaleY = 1;

    if (includeScale && element instanceof HTMLElement) {
      const { offsetWidth, offsetHeight } = element;
      scaleX = offsetWidth > 0 ? Math.round(width) / offsetWidth || 1 : 1;
      scaleY = offsetHeight > 0 ? Math.round(height) / offsetHeight || 1 : 1;
    }

    return {
      width: width / scaleX,
      height: height / scaleY,
      top: top / scaleY,
      right: right / scaleX,
      bottom: bottom / scaleY,
      left: left / scaleX,
      x: left / scaleX,
      y: top / scaleY,
    };
  }

  /**
   * Returns the `document.documentElement` or the `<html>` element.
   *
   * @param {(Node | HTMLElement | Element | globalThis)=} node
   * @returns {HTMLElement | HTMLHtmlElement}
   */
  function getDocumentElement(node) {
    return getDocument(node).documentElement;
  }

  /**
   * Utility to determine if an `HTMLElement`
   * is partially visible in viewport.
   *
   * @param {HTMLElement | Element} element target
   * @return {boolean} the query result
   */
  const isElementInScrollRange = (element) => {
    const { top, bottom } = getBoundingClientRect(element);
    const { clientHeight } = getDocumentElement(element);
    // checks bottom && top
    return top <= clientHeight && bottom >= 0;
  };

  /**
   * Checks if a page is Right To Left.
   * @param {(HTMLElement | Element)=} node the target
   * @returns {boolean} the query result
   */
  const isRTL = (node) => getDocumentElement(node).dir === 'rtl';

  /**
   * A shortcut for `(document|Element).querySelectorAll`.
   *
   * @param {string} selector the input selector
   * @param {(HTMLElement | Element | Document | Node)=} parent optional node to look into
   * @return {NodeListOf<HTMLElement | Element>} the query result
   */
  function querySelectorAll(selector, parent) {
    const lookUp = parent && parentNodes
      .some((x) => parent instanceof x) ? parent : getDocument();
    // @ts-ignore -- `ShadowRoot` is also a node
    return lookUp.querySelectorAll(selector);
  }

  /**
   * Shortcut for `HTMLElement.getElementsByClassName` method. Some `Node` elements
   * like `ShadowRoot` do not support `getElementsByClassName`.
   *
   * @param {string} selector the class name
   * @param {(HTMLElement | Element | Document)=} parent optional Element to look into
   * @return {HTMLCollectionOf<HTMLElement | Element>} the 'HTMLCollection'
   */
  function getElementsByClassName(selector, parent) {
    const lookUp = parent && parentNodes.some((x) => parent instanceof x)
      ? parent : getDocument();
    return lookUp.getElementsByClassName(selector);
  }

  /** @type {Map<HTMLElement | Element, any>} */
  const TimeCache = new Map();
  /**
   * An interface for one or more `TimerHandler`s per `Element`.
   * @see https://github.com/thednp/navbar.js/
   */
  const Timer = {
    /**
     * Sets a new timeout timer for an element, or element -> key association.
     * @param {HTMLElement | Element | string} target target element
     * @param {ReturnType<TimerHandler>} callback the callback
     * @param {number} delay the execution delay
     * @param {string=} key a unique key
     */
    set: (target, callback, delay, key) => {
      const element = querySelector(target);

      if (!element) return;

      if (key && key.length) {
        if (!TimeCache.has(element)) {
          TimeCache.set(element, new Map());
        }
        const keyTimers = TimeCache.get(element);
        keyTimers.set(key, setTimeout(callback, delay));
      } else {
        TimeCache.set(element, setTimeout(callback, delay));
      }
    },

    /**
     * Returns the timer associated with the target.
     * @param {HTMLElement | Element | string} target target element
     * @param {string=} key a unique
     * @returns {number?} the timer
     */
    get: (target, key) => {
      const element = querySelector(target);

      if (!element) return null;
      const keyTimers = TimeCache.get(element);

      if (key && key.length && keyTimers && keyTimers.get) {
        return keyTimers.get(key) || null;
      }
      return keyTimers || null;
    },

    /**
     * Clears the element's timer.
     * @param {HTMLElement | Element | string} target target element
     * @param {string=} key a unique key
     */
    clear: (target, key) => {
      const element = querySelector(target);

      if (!element) return;

      if (key && key.length) {
        const keyTimers = TimeCache.get(element);

        if (keyTimers && keyTimers.get) {
          clearTimeout(keyTimers.get(key));
          keyTimers.delete(key);
          if (keyTimers.size === 0) {
            TimeCache.delete(element);
          }
        }
      } else {
        clearTimeout(TimeCache.get(element));
        TimeCache.delete(element);
      }
    },
  };

  /**
   * Utility to force re-paint of an `HTMLElement` target.
   *
   * @param {HTMLElement | Element} element is the target
   * @return {number} the `Element.offsetHeight` value
   */
  // @ts-ignore
  const reflow = (element) => element.offsetHeight;

  /**
   * A global namespace for most scroll event listeners.
   * @type {Partial<AddEventListenerOptions>}
   */
  const passiveHandler = { passive: true };

  /**
   * Global namespace for most components `target` option.
   */
  const dataBsTarget = 'data-bs-target';

  /** @type {string} */
  const carouselString = 'carousel';

  /** @type {string} */
  const carouselComponent = 'Carousel';

  /**
   * Global namespace for most components `parent` option.
   */
  const dataBsParent = 'data-bs-parent';

  /**
   * Global namespace for most components `container` option.
   */
  const dataBsContainer = 'data-bs-container';

  /**
   * Returns the `Element` that THIS one targets
   * via `data-bs-target`, `href`, `data-bs-parent` or `data-bs-container`.
   *
   * @param {HTMLElement | Element} element the target element
   * @returns {(HTMLElement | Element)?} the query result
   */
  function getTargetElement(element) {
    const targetAttr = [dataBsTarget, dataBsParent, dataBsContainer, 'href'];
    const doc = getDocument(element);

    return targetAttr.map((att) => {
      const attValue = getAttribute(element, att);
      if (attValue) {
        return att === dataBsParent ? closest(element, attValue) : querySelector(attValue, doc);
      }
      return null;
    }).filter((x) => x)[0];
  }

  /* Native JavaScript for Bootstrap 5 | Carousel
  ----------------------------------------------- */

  // CAROUSEL PRIVATE GC
  // ===================
  const carouselSelector = `[data-bs-ride="${carouselString}"]`;
  const carouselItem = `${carouselString}-item`;
  const dataBsSlideTo = 'data-bs-slide-to';
  const dataBsSlide = 'data-bs-slide';
  const pausedClass = 'paused';

  const carouselDefaults = {
    pause: 'hover',
    keyboard: false,
    touch: true,
    interval: 5000,
  };

  /**
   * Static method which returns an existing `Carousel` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Carousel>}
   */
  const getCarouselInstance = (element) => getInstance(element, carouselComponent);

  /**
   * A `Carousel` initialization callback.
   * @type {BSN.InitCallback<Carousel>}
   */
  const carouselInitCallback = (element) => new Carousel(element);

  let startX = 0;
  let currentX = 0;
  let endX = 0;

  // CAROUSEL CUSTOM EVENTS
  // ======================
  const carouselSlideEvent = OriginalEvent(`slide.bs.${carouselString}`);
  const carouselSlidEvent = OriginalEvent(`slid.bs.${carouselString}`);

  // CAROUSEL EVENT HANDLERS
  // =======================
  /**
   * The `transitionend` event listener of the `Carousel`.
   * @param {Carousel} self the `Carousel` instance
   */
  function carouselTransitionEndHandler(self) {
    const {
      index, direction, element, slides, options,
    } = self;

    // discontinue disposed instances
    if (self.isAnimating && getCarouselInstance(element)) {
      const activeItem = getActiveIndex(self);
      const orientation = direction === 'left' ? 'next' : 'prev';
      const directionClass = direction === 'left' ? 'start' : 'end';

      addClass(slides[index], activeClass);
      removeClass(slides[index], `${carouselItem}-${orientation}`);
      removeClass(slides[index], `${carouselItem}-${directionClass}`);

      removeClass(slides[activeItem], activeClass);
      removeClass(slides[activeItem], `${carouselItem}-${directionClass}`);

      dispatchEvent(element, carouselSlidEvent);
      Timer.clear(element, dataBsSlide);

      // check for element, might have been disposed
      if (!getDocument(element).hidden && options.interval
        && !self.isPaused) {
        self.cycle();
      }
    }
  }

  /**
   * Handles the `mouseenter` / `touchstart` events when *options.pause*
   * is set to `hover`.
   *
   * @this {HTMLElement | Element}
   */
  function carouselPauseHandler() {
    const element = this;
    const self = getCarouselInstance(element);

    if (self && !self.isPaused && !Timer.get(element, pausedClass)) {
      addClass(element, pausedClass);
    }
  }

  /**
   * Handles the `mouseleave` / `touchend` events when *options.pause*
   * is set to `hover`.
   *
   * @this {HTMLElement | Element}
   */
  function carouselResumeHandler() {
    const element = this;
    const self = getCarouselInstance(element);

    if (self && self.isPaused && !Timer.get(element, pausedClass)) {
      self.cycle();
    }
  }

  /**
   * Handles the `click` event for the `Carousel` indicators.
   *
   * @this {HTMLElement}
   * @param {MouseEvent} e the `Event` object
   */
  function carouselIndicatorHandler(e) {
    e.preventDefault();
    const indicator = this;
    const element = closest(indicator, carouselSelector) || getTargetElement(indicator);
    if (!element) return;
    const self = getCarouselInstance(element);

    if (!self || self.isAnimating) return;

    // @ts-ignore
    const newIndex = +getAttribute(indicator, dataBsSlideTo);

    if (indicator && !hasClass(indicator, activeClass) // event target is not active
      && !Number.isNaN(newIndex)) { // AND has the specific attribute
      self.to(newIndex); // do the slide
    }
  }

  /**
   * Handles the `click` event for the `Carousel` arrows.
   *
   * @this {HTMLElement}
   * @param {MouseEvent} e the `Event` object
   */
  function carouselControlsHandler(e) {
    e.preventDefault();
    const control = this;
    const element = closest(control, carouselSelector) || getTargetElement(control);
    const self = element && getCarouselInstance(element);
    if (!self || self.isAnimating) return;
    const orientation = getAttribute(control, dataBsSlide);

    if (orientation === 'next') {
      self.next();
    } else if (orientation === 'prev') {
      self.prev();
    }
  }

  /**
   * Handles the keyboard `keydown` event for the visible `Carousel` elements.
   *
   * @param {KeyboardEvent} e the `Event` object
   */
  function carouselKeyHandler({ code }) {
    const [element] = [...querySelectorAll(carouselSelector)]
      .filter((x) => isElementInScrollRange(x));

    const self = getCarouselInstance(element);
    if (!self) return;
    const RTL = isRTL();
    const arrowKeyNext = !RTL ? keyArrowRight : keyArrowLeft;
    const arrowKeyPrev = !RTL ? keyArrowLeft : keyArrowRight;

    if (code === arrowKeyPrev) self.prev();
    else if (code === arrowKeyNext) self.next();
  }

  // CAROUSEL TOUCH HANDLERS
  // =======================
  /**
   * Handles the `touchdown` event for the `Carousel` element.
   *
   * @this {HTMLElement | Element}
   * @param {TouchEvent} e the `Event` object
   */
  function carouselTouchDownHandler(e) {
    const element = this;
    const self = getCarouselInstance(element);

    if (!self || self.isTouch) { return; }

    startX = e.changedTouches[0].pageX;

    // @ts-ignore
    if (element.contains(e.target)) {
      self.isTouch = true;
      toggleCarouselTouchHandlers(self, true);
    }
  }

  /**
   * Handles the `touchmove` event for the `Carousel` element.
   *
   * @this {HTMLElement | Element}
   * @param {TouchEvent} e
   */
  function carouselTouchMoveHandler(e) {
    const { changedTouches, type } = e;
    const self = getCarouselInstance(this);

    if (!self || !self.isTouch) { return; }

    currentX = changedTouches[0].pageX;

    // cancel touch if more than one changedTouches detected
    if (type === touchmoveEvent && changedTouches.length > 1) {
      e.preventDefault();
    }
  }

  /**
   * Handles the `touchend` event for the `Carousel` element.
   *
   * @this {HTMLElement | Element}

   * @param {TouchEvent} e
   */
  function carouselTouchEndHandler(e) {
    const element = this;
    const self = getCarouselInstance(element);

    if (!self || !self.isTouch) { return; }

    endX = currentX || e.changedTouches[0].pageX;

    if (self.isTouch) {
      // the event target is outside the carousel OR carousel doens't include the related target
      // @ts-ignore
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
  /**
   * Sets active indicator for the `Carousel` instance.
   * @param {Carousel} self the `Carousel` instance
   * @param {number} pageIndex the index of the new active indicator
   */
  function activateCarouselIndicator(self, pageIndex) {
    const { indicators } = self;
    [...indicators].forEach((x) => removeClass(x, activeClass));

    if (self.indicators[pageIndex]) addClass(indicators[pageIndex], activeClass);
  }

  /**
   * Toggles the touch event listeners for a given `Carousel` instance.
   * @param {Carousel} self the `Carousel` instance
   * @param {boolean=} add when `TRUE` event listeners are added
   */
  function toggleCarouselTouchHandlers(self, add) {
    const { element } = self;
    const action = add ? addListener : removeListener;
    action(element, touchmoveEvent, carouselTouchMoveHandler, passiveHandler);
    action(element, touchendEvent, carouselTouchEndHandler, passiveHandler);
  }

  /**
   * Toggles all event listeners for a given `Carousel` instance.
   * @param {Carousel} self the `Carousel` instance
   * @param {boolean=} add when `TRUE` event listeners are added
   */
  function toggleCarouselHandlers(self, add) {
    const {
      element, options, slides, controls, indicators,
    } = self;
    const {
      touch, pause, interval, keyboard,
    } = options;
    const action = add ? addListener : removeListener;

    if (pause && interval) {
      action(element, mouseenterEvent, carouselPauseHandler);
      action(element, mouseleaveEvent, carouselResumeHandler);
      action(element, touchstartEvent, carouselPauseHandler, passiveHandler);
      action(element, touchendEvent, carouselResumeHandler, passiveHandler);
    }

    if (touch && slides.length > 1) {
      action(element, touchstartEvent, carouselTouchDownHandler, passiveHandler);
    }

    if (controls.length) {
      controls.forEach((arrow) => {
        if (arrow) action(arrow, mouseclickEvent, carouselControlsHandler);
      });
    }

    if (indicators.length) {
      indicators.forEach((indicator) => {
        action(indicator, mouseclickEvent, carouselIndicatorHandler);
      });
    }
    // @ts-ignore
    if (keyboard) action(getWindow(element), keydownEvent, carouselKeyHandler);
  }

  /**
   * Returns the index of the current active item.
   * @param {Carousel} self the `Carousel` instance
   * @returns {number} the query result
   */
  function getActiveIndex(self) {
    const { slides, element } = self;
    const activeItem = querySelector(`.${carouselItem}.${activeClass}`, element);
    // @ts-ignore
    return [...slides].indexOf(activeItem);
  }

  // CAROUSEL DEFINITION
  // ===================
  /** Creates a new `Carousel` instance. */
  class Carousel extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target mostly a `.carousel` element
     * @param {BSN.Options.Carousel=} config instance options
     */
    constructor(target, config) {
      super(target, config);
      // bind
      const self = this;

      // additional properties
      /** @type {string} */
      self.direction = isRTL() ? 'right' : 'left';
      /** @type {number} */
      self.index = 0;
      /** @type {boolean} */
      self.isTouch = false;

      // initialization element
      const { element } = self;
      // carousel elements
      // a LIVE collection is prefferable
      self.slides = getElementsByClassName(carouselItem, element);
      const { slides } = self;

      // invalidate when not enough items
      // no need to go further
      if (slides.length < 2) { return; }

      self.controls = [
        ...querySelectorAll(`[${dataBsSlide}]`, element),
        ...querySelectorAll(`[${dataBsSlide}][${dataBsTarget}="#${element.id}"]`),
      ];

      /** @type {(HTMLElement | Element)?} */
      self.indicator = querySelector(`.${carouselString}-indicators`, element);

      // a LIVE collection is prefferable
      /** @type {(HTMLElement | Element)[]} */
      self.indicators = [
        ...(self.indicator ? querySelectorAll(`[${dataBsSlideTo}]`, self.indicator) : []),
        ...querySelectorAll(`[${dataBsSlideTo}][${dataBsTarget}="#${element.id}"]`),
      ];

      // set JavaScript and DATA API options
      const { options } = self;

      // don't use TRUE as interval, it's actually 0, use the default 5000ms better
      self.options.interval = options.interval === true
        ? carouselDefaults.interval
        : options.interval;

      // set first slide active if none
      if (getActiveIndex(self) < 0) {
        if (slides.length) addClass(slides[0], activeClass);
        if (self.indicators.length) activateCarouselIndicator(self, 0);
      }

      // attach event handlers
      toggleCarouselHandlers(self, true);

      // start to cycle if interval is set
      if (options.interval) self.cycle();
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return carouselComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return carouselDefaults; }
    /* eslint-enable */

    /**
     * Check if instance is paused.
     * @returns {boolean}
    */
    get isPaused() {
      return hasClass(this.element, pausedClass);
    }

    /**
     * Check if instance is animating.
     * @returns {boolean}
    */
    get isAnimating() {
      return querySelector(`.${carouselItem}-next,.${carouselItem}-prev`, this.element) !== null;
    }

    // CAROUSEL PUBLIC METHODS
    // =======================
    /** Slide automatically through items. */
    cycle() {
      const self = this;
      const { element, options, isPaused } = self;

      Timer.clear(element, carouselString);
      if (isPaused) {
        Timer.clear(element, pausedClass);
        removeClass(element, pausedClass);
      }

      Timer.set(element, () => {
        if (!self.isPaused && isElementInScrollRange(element)) {
          self.index += 1;
          self.to(self.index);
        }
      }, options.interval, carouselString);
    }

    /** Pause the automatic cycle. */
    pause() {
      const self = this;
      const { element, options } = self;
      if (!self.isPaused && options.interval) {
        addClass(element, pausedClass);
        Timer.set(element, () => {}, 1, pausedClass);
      }
    }

    /** Slide to the next item. */
    next() {
      const self = this;
      if (!self.isAnimating) { self.index += 1; self.to(self.index); }
    }

    /** Slide to the previous item. */
    prev() {
      const self = this;
      if (!self.isAnimating) { self.index -= 1; self.to(self.index); }
    }

    /**
     * Jump to the item with the `idx` index.
     * @param {number} idx the index of the item to jump to
     */
    to(idx) {
      const self = this;
      const {
        element, slides, options,
      } = self;
      const activeItem = getActiveIndex(self);
      const RTL = isRTL();
      let next = idx;

      // when controled via methods, make sure to check again
      // first return if we're on the same item #227
      if (self.isAnimating || activeItem === next) return;

      // determine transition direction
      if ((activeItem < next) || (activeItem === 0 && next === slides.length - 1)) {
        self.direction = RTL ? 'right' : 'left'; // next
      } else if ((activeItem > next) || (activeItem === slides.length - 1 && next === 0)) {
        self.direction = RTL ? 'left' : 'right'; // prev
      }
      const { direction } = self;

      // find the right next index
      if (next < 0) { next = slides.length - 1; } else if (next >= slides.length) { next = 0; }

      // orientation, class name, eventProperties
      const orientation = direction === 'left' ? 'next' : 'prev';
      const directionClass = direction === 'left' ? 'start' : 'end';

      const eventProperties = {
        relatedTarget: slides[next],
        from: activeItem,
        to: next,
        direction,
      };

      // update event properties
      ObjectAssign(carouselSlideEvent, eventProperties);
      ObjectAssign(carouselSlidEvent, eventProperties);

      // discontinue when prevented
      dispatchEvent(element, carouselSlideEvent);
      if (carouselSlideEvent.defaultPrevented) return;

      // update index
      self.index = next;
      activateCarouselIndicator(self, next);

      if (getElementTransitionDuration(slides[next]) && hasClass(element, 'slide')) {
        Timer.set(element, () => {
          addClass(slides[next], `${carouselItem}-${orientation}`);
          reflow(slides[next]);
          addClass(slides[next], `${carouselItem}-${directionClass}`);
          addClass(slides[activeItem], `${carouselItem}-${directionClass}`);

          emulateTransitionEnd(slides[next], () => carouselTransitionEndHandler(self));
        }, 17, dataBsSlide);
      } else {
        addClass(slides[next], activeClass);
        removeClass(slides[activeItem], activeClass);

        Timer.set(element, () => {
          Timer.clear(element, dataBsSlide);
          // check for element, might have been disposed
          if (element && options.interval && !self.isPaused) {
            self.cycle();
          }

          dispatchEvent(element, carouselSlidEvent);
        }, 17, dataBsSlide);
      }
    }

    /** Remove `Carousel` component from target. */
    dispose() {
      const self = this;
      const { slides } = self;
      const itemClasses = ['start', 'end', 'prev', 'next'];

      [...slides].forEach((slide, idx) => {
        if (hasClass(slide, activeClass)) activateCarouselIndicator(self, idx);
        itemClasses.forEach((c) => removeClass(slide, `${carouselItem}-${c}`));
      });

      toggleCarouselHandlers(self);
      super.dispose();
    }
  }

  ObjectAssign(Carousel, {
    selector: carouselSelector,
    init: carouselInitCallback,
    getInstance: getCarouselInstance,
  });

  /**
   * A global namespace for aria-expanded.
   * @type {string}
   */
  const ariaExpanded = 'aria-expanded';

  /**
   * Global namespace for most components `collapsing` class.
   * As used by `Collapse` / `Tab`.
   */
  const collapsingClass = 'collapsing';

  /** @type {string} */
  const collapseString = 'collapse';

  /** @type {string} */
  const collapseComponent = 'Collapse';

  /* Native JavaScript for Bootstrap 5 | Collapse
  ----------------------------------------------- */

  // COLLAPSE GC
  // ===========
  const collapseSelector = `.${collapseString}`;
  const collapseToggleSelector = `[${dataBsToggle}="${collapseString}"]`;
  const collapseDefaults = { parent: null };

  /**
   * Static method which returns an existing `Collapse` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Collapse>}
   */
  const getCollapseInstance = (element) => getInstance(element, collapseComponent);

  /**
   * A `Collapse` initialization callback.
   * @type {BSN.InitCallback<Collapse>}
   */
  const collapseInitCallback = (element) => new Collapse(element);

  // COLLAPSE CUSTOM EVENTS
  // ======================
  const showCollapseEvent = OriginalEvent(`show.bs.${collapseString}`);
  const shownCollapseEvent = OriginalEvent(`shown.bs.${collapseString}`);
  const hideCollapseEvent = OriginalEvent(`hide.bs.${collapseString}`);
  const hiddenCollapseEvent = OriginalEvent(`hidden.bs.${collapseString}`);

  // COLLAPSE PRIVATE METHODS
  // ========================
  /**
   * Expand the designated `Element`.
   * @param {Collapse} self the `Collapse` instance
   */
  function expandCollapse(self) {
    const {
      element, parent, triggers,
    } = self;

    dispatchEvent(element, showCollapseEvent);
    if (showCollapseEvent.defaultPrevented) return;

    Timer.set(element, () => {}, 17);
    if (parent) Timer.set(parent, () => {}, 17);

    addClass(element, collapsingClass);
    removeClass(element, collapseString);

    // @ts-ignore
    element.style.height = `${element.scrollHeight}px`;

    emulateTransitionEnd(element, () => {
      Timer.clear(element);
      if (parent) Timer.clear(parent);

      triggers.forEach((btn) => setAttribute(btn, ariaExpanded, 'true'));

      removeClass(element, collapsingClass);
      addClass(element, collapseString);
      addClass(element, showClass);

      // @ts-ignore
      element.style.height = '';

      dispatchEvent(element, shownCollapseEvent);
    });
  }

  /**
   * Collapse the designated `Element`.
   * @param {Collapse} self the `Collapse` instance
   */
  function collapseContent(self) {
    const {
      // @ts-ignore
      element, parent, triggers,
    } = self;

    dispatchEvent(element, hideCollapseEvent);

    if (hideCollapseEvent.defaultPrevented) return;

    Timer.set(element, () => {}, 17);
    if (parent) Timer.set(parent, () => {}, 17);

    // @ts-ignore
    element.style.height = `${element.scrollHeight}px`;

    removeClass(element, collapseString);
    removeClass(element, showClass);
    addClass(element, collapsingClass);

    reflow(element);
    // @ts-ignore
    element.style.height = '0px';

    emulateTransitionEnd(element, () => {
      Timer.clear(element);
      if (parent) Timer.clear(parent);

      triggers.forEach((btn) => setAttribute(btn, ariaExpanded, 'false'));

      removeClass(element, collapsingClass);
      addClass(element, collapseString);

      // @ts-ignore
      element.style.height = '';

      dispatchEvent(element, hiddenCollapseEvent);
    });
  }

  /**
   * Toggles on/off the event listener(s) of the `Collapse` instance.
   * @param {Collapse} self the `Collapse` instance
   * @param {boolean=} add when `true`, the event listener is added
   */
  function toggleCollapseHandler(self, add) {
    const action = add ? addListener : removeListener;
    const { triggers } = self;

    if (triggers.length) {
      triggers.forEach((btn) => action(btn, mouseclickEvent, collapseClickHandler));
    }
  }

  // COLLAPSE EVENT HANDLER
  // ======================
  /**
   * Handles the `click` event for the `Collapse` instance.
   * @param {MouseEvent} e the `Event` object
   */
  function collapseClickHandler(e) {
    const { target } = e; // @ts-ignore - our target is `HTMLElement`
    const trigger = target && closest(target, collapseToggleSelector);
    const element = trigger && getTargetElement(trigger);
    const self = element && getCollapseInstance(element);
    if (self) self.toggle();

    // event target is anchor link #398
    if (trigger && trigger.tagName === 'A') e.preventDefault();
  }

  // COLLAPSE DEFINITION
  // ===================

  /** Returns a new `Colapse` instance. */
  class Collapse extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target and `Element` that matches the selector
     * @param {BSN.Options.Collapse=} config instance options
     */
    constructor(target, config) {
      super(target, config);
      // bind
      const self = this;

      // initialization element
      const { element, options } = self;

      // set triggering elements
      /** @type {(HTMLElement | Element)[]} */
      self.triggers = [...querySelectorAll(collapseToggleSelector)]
        .filter((btn) => getTargetElement(btn) === element);

      // set parent accordion
      /** @type {(HTMLElement | Element)?} */
      self.parent = querySelector(options.parent);

      // add event listeners
      toggleCollapseHandler(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return collapseComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return collapseDefaults; }
    /* eslint-enable */

    // COLLAPSE PUBLIC METHODS
    // =======================
    /** Toggles the visibility of the collapse. */
    toggle() {
      const self = this;
      if (!hasClass(self.element, showClass)) self.show();
      else self.hide();
    }

    /** Hides the collapse. */
    hide() {
      const self = this;
      const { triggers, element } = self;
      if (Timer.get(element)) return;

      collapseContent(self);
      if (triggers.length) {
        triggers.forEach((btn) => addClass(btn, `${collapseString}d`));
      }
    }

    /** Shows the collapse. */
    show() {
      const self = this;
      const {
        element, parent, triggers,
      } = self;
      let activeCollapse;
      let activeCollapseInstance;

      if (parent) {
        activeCollapse = [...querySelectorAll(`.${collapseString}.${showClass}`, parent)]
          .find((i) => getCollapseInstance(i));
        activeCollapseInstance = activeCollapse && getCollapseInstance(activeCollapse);
      }

      if ((!parent || (parent && !Timer.get(parent))) && !Timer.get(element)) {
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

    /** Remove the `Collapse` component from the target `Element`. */
    dispose() {
      const self = this;
      toggleCollapseHandler(self);

      super.dispose();
    }
  }

  ObjectAssign(Collapse, {
    selector: collapseSelector,
    init: collapseInitCallback,
    getInstance: getCollapseInstance,
  });

  /**
   * A global namespace for `focus` event.
   * @type {string}
   */
  const focusEvent = 'focus';

  /**
   * A global namespace for `keyup` event.
   * @type {string}
   */
  const keyupEvent = 'keyup';

  /**
   * A global namespace for `scroll` event.
   * @type {string}
   */
  const scrollEvent = 'scroll';

  /**
   * A global namespace for `resize` event.
   * @type {string}
   */
  const resizeEvent = 'resize';

  /**
   * A global namespace for `ArrowUp` key.
   * @type {string} e.which = 38 equivalent
   */
  const keyArrowUp = 'ArrowUp';

  /**
   * A global namespace for `ArrowDown` key.
   * @type {string} e.which = 40 equivalent
   */
  const keyArrowDown = 'ArrowDown';

  /**
   * A global namespace for `Escape` key.
   * @type {string} e.which = 27 equivalent
   */
  const keyEscape = 'Escape';

  /**
   * Shortcut for `HTMLElement.hasAttribute()` method.
   * @param  {HTMLElement | Element} element target element
   * @param  {string} attribute attribute name
   * @returns {boolean} the query result
   */
  const hasAttribute = (element, attribute) => element.hasAttribute(attribute);

  /**
   * Shortcut for multiple uses of `HTMLElement.style.propertyName` method.
   * @param  {HTMLElement | Element} element target element
   * @param  {Partial<CSSStyleDeclaration>} styles attribute value
   */
  // @ts-ignore
  const setElementStyle = (element, styles) => { ObjectAssign(element.style, styles); };

  /**
   * Utility to focus an `HTMLElement` target.
   *
   * @param {HTMLElement | Element} element is the target
   */
  // @ts-ignore -- `Element`s resulted from querySelector can focus too
  const focus = (element) => element.focus();

  /**
   * Global namespace for `Dropdown` types / classes.
   */
  const dropdownMenuClasses = ['dropdown', 'dropup', 'dropstart', 'dropend'];

  /** @type {string} */
  const dropdownComponent = 'Dropdown';

  /**
   * Global namespace for `.dropdown-menu`.
   */
  const dropdownMenuClass = 'dropdown-menu';

  /**
   * Checks if an *event.target* or its parent has an `href="#"` value.
   * We need to prevent jumping around onclick, don't we?
   *
   * @param {HTMLElement | HTMLAnchorElement | EventTarget} element the target element
   * @returns {boolean} the query result
   */
  function isEmptyAnchor(element) {
    // @ts-ignore -- `EventTarget` must be `HTMLElement`
    const parentAnchor = closest(element, 'A');
    // @ts-ignore -- anchor href starts with #
    return element && ((hasAttribute(element, 'href') && element.href.slice(-1) === '#')
      // @ts-ignore -- OR a child of an anchor with href starts with #
      || (parentAnchor && hasAttribute(parentAnchor, 'href') && parentAnchor.href.slice(-1) === '#'));
  }

  /* Native JavaScript for Bootstrap 5 | Dropdown
  ----------------------------------------------- */

  // DROPDOWN PRIVATE GC
  // ===================
  const [
    dropdownString,
    dropupString,
    dropstartString,
    dropendString,
  ] = dropdownMenuClasses;
  const dropdownSelector = `[${dataBsToggle}="${dropdownString}"]`;

  /**
   * Static method which returns an existing `Dropdown` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Dropdown>}
   */
  const getDropdownInstance = (element) => getInstance(element, dropdownComponent);

  /**
   * A `Dropdown` initialization callback.
   * @type {BSN.InitCallback<Dropdown>}
   */
  const dropdownInitCallback = (element) => new Dropdown(element);

  // DROPDOWN PRIVATE GC
  // ===================
  const dropdownMenuEndClass = `${dropdownMenuClass}-end`;
  const verticalClass = [dropdownString, dropupString];
  const horizontalClass = [dropstartString, dropendString];
  const menuFocusTags = ['A', 'BUTTON'];

  const dropdownDefaults = {
    offset: 5, // [number] 5(px)
    display: 'dynamic', // [dynamic|static]
  };

  // DROPDOWN CUSTOM EVENTS
  // ======================
  const showDropdownEvent = OriginalEvent(`show.bs.${dropdownString}`);
  const shownDropdownEvent = OriginalEvent(`shown.bs.${dropdownString}`);
  const hideDropdownEvent = OriginalEvent(`hide.bs.${dropdownString}`);
  const hiddenDropdownEvent = OriginalEvent(`hidden.bs.${dropdownString}`);

  // DROPDOWN PRIVATE METHODS
  // ========================
  /**
   * Apply specific style or class names to a `.dropdown-menu` to automatically
   * accomodate the layout and the page scroll.
   *
   * @param {Dropdown} self the `Dropdown` instance
   */
  function styleDropdown(self) {
    const {
      element, menu, parentElement, options,
    } = self;
    const { offset } = options;

    // don't apply any style on mobile view
    if (getElementStyle(menu, 'position') === 'static') return;

    const RTL = isRTL(element);
    const menuEnd = hasClass(parentElement, dropdownMenuEndClass);

    // reset menu offset and position
    const resetProps = ['margin', 'top', 'bottom', 'left', 'right'];
    // @ts-ignore
    resetProps.forEach((p) => { menu.style[p] = ''; });

    // set initial position class
    // take into account .btn-group parent as .dropdown
    let positionClass = dropdownMenuClasses.find((c) => hasClass(parentElement, c)) || dropdownString;

    /** @type {Record<string, Record<string, any>>} */
    let dropdownMargin = {
      dropdown: [offset, 0, 0],
      dropup: [0, 0, offset],
      dropstart: RTL ? [-1, 0, 0, offset] : [-1, offset, 0],
      dropend: RTL ? [-1, offset, 0] : [-1, 0, 0, offset],
    };

    /** @type {Record<string, Record<string, any>>} */
    const dropdownPosition = {
      dropdown: { top: '100%' },
      dropup: { top: 'auto', bottom: '100%' },
      dropstart: RTL ? { left: '100%', right: 'auto' } : { left: 'auto', right: '100%' },
      dropend: RTL ? { left: 'auto', right: '100%' } : { left: '100%', right: 'auto' },
      menuEnd: RTL ? { right: 'auto', left: 0 } : { right: 0, left: 'auto' },
    };

    // @ts-ignore
    const { offsetWidth: menuWidth, offsetHeight: menuHeight } = menu;

    const { clientWidth, clientHeight } = getDocumentElement(element);
    const {
      left: targetLeft, top: targetTop,
      width: targetWidth, height: targetHeight,
    } = getBoundingClientRect(element);

    // dropstart | dropend
    const leftFullExceed = targetLeft - menuWidth - offset < 0;
    // dropend
    const rightFullExceed = targetLeft + menuWidth + targetWidth + offset >= clientWidth;
    // dropstart | dropend
    const bottomExceed = targetTop + menuHeight + offset >= clientHeight;
    // dropdown
    const bottomFullExceed = targetTop + menuHeight + targetHeight + offset >= clientHeight;
    // dropup
    const topExceed = targetTop - menuHeight - offset < 0;
    // dropdown / dropup
    const leftExceed = ((!RTL && menuEnd) || (RTL && !menuEnd))
      && targetLeft + targetWidth - menuWidth < 0;
    const rightExceed = ((RTL && menuEnd) || (!RTL && !menuEnd))
      && targetLeft + menuWidth >= clientWidth;

    // recompute position
    // handle RTL as well
    if (horizontalClass.includes(positionClass) && leftFullExceed && rightFullExceed) {
      positionClass = dropdownString;
    }
    if (positionClass === dropstartString && (!RTL ? leftFullExceed : rightFullExceed)) {
      positionClass = dropendString;
    }
    if (positionClass === dropendString && (RTL ? leftFullExceed : rightFullExceed)) {
      positionClass = dropstartString;
    }
    if (positionClass === dropupString && topExceed && !bottomFullExceed) {
      positionClass = dropdownString;
    }
    if (positionClass === dropdownString && bottomFullExceed && !topExceed) {
      positionClass = dropupString;
    }
    // override position for horizontal classes
    if (horizontalClass.includes(positionClass) && bottomExceed) {
      ObjectAssign(dropdownPosition[positionClass], {
        top: 'auto', bottom: 0,
      });
    }
    // override position for vertical classes
    if (verticalClass.includes(positionClass) && (leftExceed || rightExceed)) {
      // don't realign when menu is wider than window
      // in both RTL and non-RTL readability is KING
      if (targetLeft + targetWidth + Math.abs(menuWidth - targetWidth) + offset < clientWidth) {
        ObjectAssign(dropdownPosition[positionClass],
          leftExceed ? { left: 0, right: 'auto' } : { left: 'auto', right: 0 });
      }
    }

    dropdownMargin = dropdownMargin[positionClass];
    // @ts-ignore
    menu.style.margin = `${dropdownMargin.map((x) => (x ? `${x}px` : x)).join(' ')}`;

    setElementStyle(menu, dropdownPosition[positionClass]);

    // update dropdown-menu-end
    if (hasClass(menu, dropdownMenuEndClass)) {
      setElementStyle(menu, dropdownPosition.menuEnd);
    }
  }

  /**
   * Returns an `Array` of focusable items in the given dropdown-menu.
   * @param {HTMLElement | Element} menu
   * @returns {(HTMLElement | Element)[]}
   */
  function getMenuItems(menu) {
    // @ts-ignore
    return [...menu.children].map((c) => {
      if (c && menuFocusTags.includes(c.tagName)) return c;
      const { firstElementChild } = c;
      if (firstElementChild && menuFocusTags.includes(firstElementChild.tagName)) {
        return firstElementChild;
      }
      return null;
    }).filter((c) => c);
  }

  /**
   * Toggles on/off the listeners for the events that close the dropdown
   * as well as event that request a new position for the dropdown.
   *
   * @param {Dropdown} self the `Dropdown` instance
   */
  function toggleDropdownDismiss(self) {
    const { element } = self;
    const action = self.open ? addListener : removeListener;
    const doc = getDocument(element);

    action(doc, mouseclickEvent, dropdownDismissHandler);
    action(doc, focusEvent, dropdownDismissHandler);
    action(doc, keydownEvent, dropdownPreventScroll);
    action(doc, keyupEvent, dropdownKeyHandler);

    if (self.options.display === 'dynamic') {
      [scrollEvent, resizeEvent].forEach((ev) => {
        // @ts-ignore
        action(getWindow(element), ev, dropdownLayoutHandler, passiveHandler);
      });
    }
  }

  /**
   * Toggles on/off the `click` event listener of the `Dropdown`.
   *
   * @param {Dropdown} self the `Dropdown` instance
   * @param {boolean=} add when `true`, it will add the event listener
   */
  function toggleDropdownHandler(self, add) {
    const action = add ? addListener : removeListener;
    action(self.element, mouseclickEvent, dropdownClickHandler);
  }

  /**
   * Returns the currently open `.dropdown` element.
   *
   * @param {(Document | HTMLElement | Element | globalThis)=} element target
   * @returns {HTMLElement?} the query result
   */
  function getCurrentOpenDropdown(element) {
    const currentParent = [...dropdownMenuClasses, 'btn-group', 'input-group']
      .map((c) => getElementsByClassName(`${c} ${showClass}`), getDocument(element))
      .find((x) => x.length);

    if (currentParent && currentParent.length) {
      // @ts-ignore -- HTMLElement is also Element
      return [...currentParent[0].children]
        .find((x) => hasAttribute(x, dataBsToggle));
    }
    return null;
  }

  // DROPDOWN EVENT HANDLERS
  // =======================
  /**
   * Handles the `click` event for the `Dropdown` instance.
   *
   * @param {MouseEvent} e event object
   * @this {Document}
   */
  function dropdownDismissHandler(e) {
    const { target, type } = e;
    // @ts-ignore
    if (!target || !target.closest) return; // some weird FF bug #409

    // @ts-ignore
    const element = getCurrentOpenDropdown(target);
    if (!element) return;

    const self = getDropdownInstance(element);
    if (!self) return;

    const { parentElement, menu } = self;

    // @ts-ignore
    const hasData = closest(target, dropdownSelector) !== null;
    // @ts-ignore
    const isForm = parentElement && parentElement.contains(target)
      // @ts-ignore
      && (target.tagName === 'form' || closest(target, 'form') !== null);

    // @ts-ignore
    if (type === mouseclickEvent && isEmptyAnchor(target)) {
      e.preventDefault();
    }
    if (type === focusEvent // @ts-ignore
      && (target === element || target === menu || menu.contains(target))) {
      return;
    }

    if (isForm || hasData) ; else if (self) {
      self.hide();
    }
  }

  /**
   * Handles `click` event listener for `Dropdown`.
   * @this {HTMLElement | Element}
   * @param {MouseEvent} e event object
   */
  function dropdownClickHandler(e) {
    const element = this;
    const { target } = e;
    const self = getDropdownInstance(element);

    if (self) {
      self.toggle();
      if (target && isEmptyAnchor(target)) e.preventDefault();
    }
  }

  /**
   * Prevents scroll when dropdown-menu is visible.
   * @param {KeyboardEvent} e event object
   */
  function dropdownPreventScroll(e) {
    if ([keyArrowDown, keyArrowUp].includes(e.code)) e.preventDefault();
  }

  /**
   * Handles keyboard `keydown` events for `Dropdown`.
   * @param {KeyboardEvent} e keyboard key
   * @this {Document}
   */
  function dropdownKeyHandler(e) {
    const { code } = e;
    const element = getCurrentOpenDropdown(this);
    const self = element && getDropdownInstance(element);
    const activeItem = element && getDocument(element).activeElement;
    if (!self || !activeItem) return;
    const { menu, open } = self;
    const menuItems = getMenuItems(menu);

    // arrow up & down
    if (menuItems && menuItems.length && [keyArrowDown, keyArrowUp].includes(code)) {
      let idx = menuItems.indexOf(activeItem);
      if (activeItem === element) {
        idx = 0;
      } else if (code === keyArrowUp) {
        idx = idx > 1 ? idx - 1 : 0;
      } else if (code === keyArrowDown) {
        idx = idx < menuItems.length - 1 ? idx + 1 : idx;
      }
      if (menuItems[idx]) focus(menuItems[idx]);
    }

    if (keyEscape === code && open) {
      self.toggle();
      focus(element);
    }
  }

  /**
   * @this {globalThis}
   * @returns {void}
   */
  function dropdownLayoutHandler() {
    const element = getCurrentOpenDropdown(this);
    const self = element && getDropdownInstance(element);

    if (self && self.open) styleDropdown(self);
  }

  // DROPDOWN DEFINITION
  // ===================
  /** Returns a new Dropdown instance. */
  class Dropdown extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target Element or string selector
     * @param {BSN.Options.Dropdown=} config the instance options
     */
    constructor(target, config) {
      super(target, config);
      // bind
      const self = this;

      // initialization element
      const { element } = self;
      const { parentElement } = element;

      // set targets
      /** @type {(Element | HTMLElement)} */
      // @ts-ignore
      self.parentElement = parentElement;
      /** @type {(Element | HTMLElement)} */
      // @ts-ignore
      self.menu = querySelector(`.${dropdownMenuClass}`, parentElement);

      // set initial state to closed
      /** @type {boolean} */
      self.open = false;

      // add event listener
      toggleDropdownHandler(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return dropdownComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return dropdownDefaults; }
    /* eslint-enable */

    // DROPDOWN PUBLIC METHODS
    // =======================
    /** Shows/hides the dropdown menu to the user. */
    toggle() {
      const self = this;

      if (self.open) self.hide();
      else self.show();
    }

    /** Shows the dropdown menu to the user. */
    show() {
      const self = this;
      const {
        element, open, menu, parentElement,
      } = self;

      const currentElement = getCurrentOpenDropdown(element);
      const currentInstance = currentElement && getDropdownInstance(currentElement);
      if (currentInstance) currentInstance.hide();

      // dispatch
      [showDropdownEvent, shownDropdownEvent].forEach((e) => { e.relatedTarget = element; });
      dispatchEvent(parentElement, showDropdownEvent);
      if (showDropdownEvent.defaultPrevented) return;

      addClass(menu, showClass);
      addClass(parentElement, showClass);
      setAttribute(element, ariaExpanded, 'true');

      // change menu position
      styleDropdown(self);

      self.open = !open;

      setTimeout(() => {
        focus(element); // focus the element
        toggleDropdownDismiss(self);
        dispatchEvent(parentElement, shownDropdownEvent);
      }, 1);
    }

    /** Hides the dropdown menu from the user. */
    hide() {
      const self = this;
      const {
        element, open, menu, parentElement,
      } = self;
      [hideDropdownEvent, hiddenDropdownEvent].forEach((e) => { e.relatedTarget = element; });

      dispatchEvent(parentElement, hideDropdownEvent);
      if (hideDropdownEvent.defaultPrevented) return;

      removeClass(menu, showClass);
      removeClass(parentElement, showClass);
      setAttribute(element, ariaExpanded, 'false');

      self.open = !open;

      // only re-attach handler if the instance is not disposed
      setTimeout(() => toggleDropdownDismiss(self), 1);

      dispatchEvent(parentElement, hiddenDropdownEvent);
    }

    /** Removes the `Dropdown` component from the target element. */
    dispose() {
      const self = this;
      const { parentElement } = self;

      if (hasClass(parentElement, showClass) && self.open) self.hide();

      toggleDropdownHandler(self);

      super.dispose();
    }
  }

  ObjectAssign(Dropdown, {
    selector: dropdownSelector,
    init: dropdownInitCallback,
    getInstance: getDropdownInstance,
  });

  /**
   * A global namespace for aria-hidden.
   * @type {string}
   */
  const ariaHidden = 'aria-hidden';

  /**
   * A global namespace for aria-modal.
   * @type {string}
   */
  const ariaModal = 'aria-modal';

  /**
   * Shortcut for `HTMLElement.removeAttribute()` method.
   * @param  {HTMLElement | Element} element target element
   * @param  {string} attribute attribute name
   * @returns {void}
   */
  const removeAttribute = (element, attribute) => element.removeAttribute(attribute);

  /**
   * Returns the `document.body` or the `<body>` element.
   *
   * @param {(Node | HTMLElement | Element | globalThis)=} node
   * @returns {HTMLElement | HTMLBodyElement}
   */
  function getDocumentBody(node) {
    return getDocument(node).body;
  }

  /** @type {string} */
  const modalString = 'modal';

  /** @type {string} */
  const modalComponent = 'Modal';

  /**
   * Check if target is a `ShadowRoot`.
   *
   * @param {any} element target
   * @returns {boolean} the query result
   */
  const isShadowRoot = (element) => {
    const OwnElement = getWindow(element).ShadowRoot;
    return element instanceof OwnElement || element instanceof ShadowRoot;
  };

  /**
   * Returns the `parentNode` also going through `ShadowRoot`.
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {Node | HTMLElement | Element} node the target node
   * @returns {Node | HTMLElement | Element} the apropriate parent node
   */
  function getParentNode(node) {
    if (node.nodeName === 'HTML') {
      return node;
    }

    // this is a quicker (but less type safe) way to save quite some bytes from the bundle
    return (
      // @ts-ignore
      node.assignedSlot // step into the shadow DOM of the parent of a slotted node
      || node.parentNode // @ts-ignore DOM Element detected
      || (isShadowRoot(node) ? node.host : null) // ShadowRoot detected
      || getDocumentElement(node) // fallback
    );
  }

  /**
   * Check if a target element is a `<table>`, `<td>` or `<th>`.
   * @param {any} element the target element
   * @returns {boolean} the query result
   */
  const isTableElement = (element) => ['TABLE', 'TD', 'TH'].includes(element.tagName);

  /**
   * Checks if an element is an `HTMLElement`.
   *
   * @param {any} element the target object
   * @returns {boolean} the query result
   */
  const isHTMLElement = (element) => element instanceof HTMLElement;

  /**
   * Returns an `HTMLElement` to be used as default value for *options.container*
   * for `Tooltip` / `Popover` components.
   *
   * When `getOffset` is *true*, it returns the `offsetParent` for tooltip/popover
   * offsets computation similar to **floating-ui**.
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {HTMLElement | Element} element the target
   * @param {boolean=} getOffset when *true* it will return an `offsetParent`
   * @returns {HTMLElement | HTMLBodyElement | Window | globalThis} the query result
   */
  function getElementContainer(element, getOffset) {
    const majorBlockTags = ['HTML', 'BODY'];

    if (getOffset) {
      /** @type {any} */
      let { offsetParent } = element;
      const win = getWindow(element);
      // const { innerWidth } = getDocumentElement(element);

      while (offsetParent && (isTableElement(offsetParent)
        || (isHTMLElement(offsetParent)
          // we must count for both fixed & sticky
          && !['sticky', 'fixed'].includes(getElementStyle(offsetParent, 'position'))))) {
        offsetParent = offsetParent.offsetParent;
      }

      if (!offsetParent || (offsetParent
        && (majorBlockTags.includes(offsetParent.tagName)
          || getElementStyle(offsetParent, 'position') === 'static'))) {
        offsetParent = win;
      }
      return offsetParent;
    }

    /** @type {(HTMLElement)[]} */
    const containers = [];
    /** @type {any} */
    let { parentNode } = element;

    while (parentNode && !majorBlockTags.includes(parentNode.nodeName)) {
      parentNode = getParentNode(parentNode);
      if (!(isShadowRoot(parentNode) || !!parentNode.shadowRoot
        || isTableElement(parentNode))) {
        containers.push(parentNode);
      }
    }

    return containers.find((c, i) => {
      if (getElementStyle(c, 'position') !== 'relative'
        && containers.slice(i + 1).every((r) => getElementStyle(r, 'position') === 'static')) {
        return c;
      }
      return null;
    }) || getDocumentBody(element);
  }

  /**
   * Global namespace for components `fixed-top` class.
   */
  const fixedTopClass = 'fixed-top';

  /**
   * Global namespace for components `fixed-bottom` class.
   */
  const fixedBottomClass = 'fixed-bottom';

  /**
   * Global namespace for components `sticky-top` class.
   */
  const stickyTopClass = 'sticky-top';

  /**
   * Global namespace for components `position-sticky` class.
   */
  const positionStickyClass = 'position-sticky';

  /** @param {(HTMLElement | Element | Document)=} parent */
  const getFixedItems = (parent) => [
    ...getElementsByClassName(fixedTopClass, parent),
    ...getElementsByClassName(fixedBottomClass, parent),
    ...getElementsByClassName(stickyTopClass, parent),
    ...getElementsByClassName(positionStickyClass, parent),
    ...getElementsByClassName('is-fixed', parent),
  ];

  /**
   * Removes *padding* and *overflow* from the `<body>`
   * and all spacing from fixed items.
   * @param {(HTMLElement | Element)=} element the target modal/offcanvas
   */
  function resetScrollbar(element) {
    const bd = getDocumentBody(element);
    setElementStyle(bd, {
      paddingRight: '',
      overflow: '',
    });

    const fixedItems = getFixedItems(bd);

    if (fixedItems.length) {
      fixedItems.forEach((fixed) => {
        setElementStyle(fixed, {
          paddingRight: '',
          marginRight: '',
        });
      });
    }
  }

  /**
   * Returns the scrollbar width if the body does overflow
   * the window.
   * @param {(HTMLElement | Element)=} element
   * @returns {number} the value
   */
  function measureScrollbar(element) {
    const { clientWidth } = getDocumentElement(element);
    const { innerWidth } = getWindow(element);
    return Math.abs(innerWidth - clientWidth);
  }

  /**
   * Sets the `<body>` and fixed items style when modal / offcanvas
   * is shown to the user.
   *
   * @param {HTMLElement | Element} element the target modal/offcanvas
   * @param {boolean=} overflow body does overflow or not
   */
  function setScrollbar(element, overflow) {
    const bd = getDocumentBody(element);
    const bodyPad = parseInt(getElementStyle(bd, 'paddingRight'), 10);
    const isOpen = getElementStyle(bd, 'overflow') === 'hidden';
    const sbWidth = isOpen && bodyPad ? 0 : measureScrollbar(element);
    const fixedItems = getFixedItems(bd);

    if (overflow) {
      setElementStyle(bd, {
        overflow: 'hidden',
        paddingRight: `${bodyPad + sbWidth}px`,
      });

      if (fixedItems.length) {
        fixedItems.forEach((fixed) => {
          const itemPadValue = getElementStyle(fixed, 'paddingRight');
          // @ts-ignore
          fixed.style.paddingRight = `${parseInt(itemPadValue, 10) + sbWidth}px`;
          if ([stickyTopClass, positionStickyClass].some((c) => hasClass(fixed, c))) {
            const itemMValue = getElementStyle(fixed, 'marginRight');
            // @ts-ignore
            fixed.style.marginRight = `${parseInt(itemMValue, 10) - sbWidth}px`;
          }
        });
      }
    }
  }

  /** @type {string} */
  const offcanvasString = 'offcanvas';

  const backdropString = 'backdrop';
  const modalBackdropClass = `${modalString}-${backdropString}`;
  const offcanvasBackdropClass = `${offcanvasString}-${backdropString}`;
  const modalActiveSelector = `.${modalString}.${showClass}`;
  const offcanvasActiveSelector = `.${offcanvasString}.${showClass}`;

  // any document would suffice
  const overlay = getDocument().createElement('div');

  /**
   * Returns the current active modal / offcancas element.
   * @param {(HTMLElement | Element)=} element the context element
   * @returns {(HTMLElement | Element)?} the requested element
   */
  function getCurrentOpen(element) {
    return querySelector(`${modalActiveSelector},${offcanvasActiveSelector}`, getDocument(element));
  }

  /**
   * Toogles from a Modal overlay to an Offcanvas, or vice-versa.
   * @param {boolean=} isModal
   */
  function toggleOverlayType(isModal) {
    const targetClass = isModal ? modalBackdropClass : offcanvasBackdropClass;
    [modalBackdropClass, offcanvasBackdropClass].forEach((c) => {
      removeClass(overlay, c);
    });
    addClass(overlay, targetClass);
  }

  /**
   * Append the overlay to DOM.
   * @param {HTMLElement | Element} container
   * @param {boolean} hasFade
   * @param {boolean=} isModal
   */
  function appendOverlay(container, hasFade, isModal) {
    toggleOverlayType(isModal);
    container.append(overlay);
    if (hasFade) addClass(overlay, fadeClass);
  }

  /**
   * Shows the overlay to the user.
   */
  function showOverlay() {
    addClass(overlay, showClass);
    reflow(overlay);
  }

  /**
   * Hides the overlay from the user.
   */
  function hideOverlay() {
    removeClass(overlay, showClass);
  }

  /**
   * Removes the overlay from DOM.
   * @param {(HTMLElement | Element)=} element
   */
  function removeOverlay(element) {
    if (!getCurrentOpen(element)) {
      removeClass(overlay, fadeClass);
      overlay.remove();
      resetScrollbar(element);
    }
  }

  /**
   * @param {HTMLElement | Element} element target
   * @returns {boolean}
   */
  function isVisible(element) {
    return element && getElementStyle(element, 'visibility') !== 'hidden'
      // @ts-ignore
      && element.offsetParent !== null;
  }

  /* Native JavaScript for Bootstrap 5 | Modal
  -------------------------------------------- */

  // MODAL PRIVATE GC
  // ================
  const modalSelector = `.${modalString}`;
  const modalToggleSelector = `[${dataBsToggle}="${modalString}"]`;
  const modalDismissSelector = `[${dataBsDismiss}="${modalString}"]`;
  const modalStaticClass = `${modalString}-static`;

  const modalDefaults = {
    backdrop: true, // boolean|string
    keyboard: true, // boolean
  };

  /**
   * Static method which returns an existing `Modal` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Modal>}
   */
  const getModalInstance = (element) => getInstance(element, modalComponent);

  /**
   * A `Modal` initialization callback.
   * @type {BSN.InitCallback<Modal>}
   */
  const modalInitCallback = (element) => new Modal(element);

  // MODAL CUSTOM EVENTS
  // ===================
  const showModalEvent = OriginalEvent(`show.bs.${modalString}`);
  const shownModalEvent = OriginalEvent(`shown.bs.${modalString}`);
  const hideModalEvent = OriginalEvent(`hide.bs.${modalString}`);
  const hiddenModalEvent = OriginalEvent(`hidden.bs.${modalString}`);

  // MODAL PRIVATE METHODS
  // =====================
  /**
   * Applies special style for the `<body>` and fixed elements
   * when a modal instance is shown to the user.
   *
   * @param {Modal} self the `Modal` instance
   */
  function setModalScrollbar(self) {
    const { element } = self;
    const scrollbarWidth = measureScrollbar(element);
    const { clientHeight, scrollHeight } = getDocumentElement(element);
    const { clientHeight: modalHeight, scrollHeight: modalScrollHeight } = element;
    const modalOverflow = modalHeight !== modalScrollHeight;

    if (!modalOverflow && scrollbarWidth) {
      const pad = isRTL(element) ? 'paddingLeft' : 'paddingRight';
      // @ts-ignore
      element.style[pad] = `${scrollbarWidth}px`;
    }
    setScrollbar(element, (modalOverflow || clientHeight !== scrollHeight));
  }

  /**
   * Toggles on/off the listeners of events that close the modal.
   *
   * @param {Modal} self the `Modal` instance
   * @param {boolean=} add when `true`, event listeners are added
   */
  function toggleModalDismiss(self, add) {
    const action = add ? addListener : removeListener;
    const { element } = self;
    action(element, mouseclickEvent, modalDismissHandler);
    // @ts-ignore
    action(getWindow(element), resizeEvent, self.update, passiveHandler);
    action(getDocument(element), keydownEvent, modalKeyHandler);
  }

  /**
   * Toggles on/off the `click` event listener of the `Modal` instance.
   * @param {Modal} self the `Modal` instance
   * @param {boolean=} add when `true`, event listener is added
   */
  function toggleModalHandler(self, add) {
    const action = add ? addListener : removeListener;
    const { triggers } = self;

    if (triggers.length) {
      triggers.forEach((btn) => action(btn, mouseclickEvent, modalClickHandler));
    }
  }

  /**
   * Executes after a modal is hidden to the user.
   * @param {Modal} self the `Modal` instance
   */
  function afterModalHide(self) {
    const { triggers, element } = self;
    removeOverlay(element);
    // @ts-ignore
    element.style.paddingRight = '';

    if (triggers.length) {
      const visibleTrigger = triggers.find((x) => isVisible(x));
      if (visibleTrigger) focus(visibleTrigger);
    }
  }

  /**
   * Executes after a modal is shown to the user.
   * @param {Modal} self the `Modal` instance
   */
  function afterModalShow(self) {
    const { element, relatedTarget } = self;
    focus(element);
    toggleModalDismiss(self, true);

    shownModalEvent.relatedTarget = relatedTarget;
    dispatchEvent(element, shownModalEvent);
  }

  /**
   * Executes before a modal is shown to the user.
   * @param {Modal} self the `Modal` instance
   */
  function beforeModalShow(self) {
    const { element, hasFade } = self;
    // @ts-ignore
    element.style.display = 'block';

    setModalScrollbar(self);
    if (!getCurrentOpen(element)) {
      getDocumentBody(element).style.overflow = 'hidden';
    }

    addClass(element, showClass);
    removeAttribute(element, ariaHidden);
    setAttribute(element, ariaModal, 'true');

    if (hasFade) emulateTransitionEnd(element, () => afterModalShow(self));
    else afterModalShow(self);
  }

  /**
   * Executes before a modal is hidden to the user.
   * @param {Modal} self the `Modal` instance
   * @param {boolean=} force when `true` skip animation
   */
  function beforeModalHide(self, force) {
    const {
      element, options, relatedTarget, hasFade,
    } = self;

    // @ts-ignore
    element.style.display = '';

    // force can also be the transitionEvent object, we wanna make sure it's not
    // call is not forced and overlay is visible
    if (options.backdrop && !force && hasFade && hasClass(overlay, showClass)
      && !getCurrentOpen(element)) { // AND no modal is visible
      hideOverlay();
      emulateTransitionEnd(overlay, () => afterModalHide(self));
    } else {
      afterModalHide(self);
    }

    toggleModalDismiss(self);

    hiddenModalEvent.relatedTarget = relatedTarget;
    dispatchEvent(element, hiddenModalEvent);
  }

  // MODAL EVENT HANDLERS
  // ====================
  /**
   * Handles the `click` event listener for modal.
   * @param {MouseEvent} e the `Event` object
   * @this {HTMLElement | Element}
   */
  function modalClickHandler(e) {
    const { target } = e;

    const trigger = target && closest(this, modalToggleSelector);
    const element = trigger && getTargetElement(trigger);
    const self = element && getModalInstance(element);

    if (!self) return;

    if (trigger && trigger.tagName === 'A') e.preventDefault();
    self.relatedTarget = trigger;
    self.toggle();
  }

  /**
   * Handles the `keydown` event listener for modal
   * to hide the modal when user type the `ESC` key.
   *
   * @param {KeyboardEvent} e the `Event` object
   */
  function modalKeyHandler({ code }) {
    const element = querySelector(modalActiveSelector);
    const self = element && getModalInstance(element);
    if (!self) return;
    const { options } = self;
    if (options.keyboard && code === keyEscape // the keyboard option is enabled and the key is 27
      && hasClass(element, showClass)) { // the modal is not visible
      self.relatedTarget = null;
      self.hide();
    }
  }

  /**
   * Handles the `click` event listeners that hide the modal.
   *
   * @this {HTMLElement | Element}
   * @param {MouseEvent} e the `Event` object
   */
  function modalDismissHandler(e) {
    const element = this;
    const self = getModalInstance(element);

    // this timer is needed
    if (!self || Timer.get(element)) return;

    const { options, isStatic, modalDialog } = self;
    const { backdrop } = options;
    const { target } = e;

    // @ts-ignore
    const selectedText = getDocument(element).getSelection().toString().length;
    // @ts-ignore
    const targetInsideDialog = modalDialog.contains(target);
    // @ts-ignore
    const dismiss = target && closest(target, modalDismissSelector);

    if (isStatic && !targetInsideDialog) {
      Timer.set(element, () => {
        addClass(element, modalStaticClass);
        emulateTransitionEnd(modalDialog, () => staticTransitionEnd(self));
      }, 17);
    } else if (dismiss || (!selectedText && !isStatic && !targetInsideDialog && backdrop)) {
      self.relatedTarget = dismiss || null;
      self.hide();
      e.preventDefault();
    }
  }

  /**
   * Handles the `transitionend` event listeners for `Modal`.
   *
   * @param {Modal} self the `Modal` instance
   */
  function staticTransitionEnd(self) {
    const { element, modalDialog } = self;
    const duration = getElementTransitionDuration(modalDialog) + 17;
    removeClass(element, modalStaticClass);
    // user must wait for zoom out transition
    Timer.set(element, () => Timer.clear(element), duration);
  }

  // MODAL DEFINITION
  // ================
  /** Returns a new `Modal` instance. */
  class Modal extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target usually the `.modal` element
     * @param {BSN.Options.Modal=} config instance options
     */
    constructor(target, config) {
      super(target, config);

      // bind
      const self = this;

      // the modal
      const { element } = self;

      // the modal-dialog
      /** @type {(HTMLElement | Element)} */
      // @ts-ignore
      self.modalDialog = querySelector(`.${modalString}-dialog`, element);

      // modal can have multiple triggering elements
      /** @type {(HTMLElement | Element)[]} */
      self.triggers = [...querySelectorAll(modalToggleSelector)]
        .filter((btn) => getTargetElement(btn) === element);

      // additional internals
      /** @type {boolean} */
      self.isStatic = self.options.backdrop === 'static';
      /** @type {boolean} */
      self.hasFade = hasClass(element, fadeClass);
      /** @type {(HTMLElement | Element)?} */
      self.relatedTarget = null;
      /** @type {HTMLBodyElement | HTMLElement | Element} */
      // @ts-ignore
      self.container = getElementContainer(element);

      // attach event listeners
      toggleModalHandler(self, true);

      // bind
      self.update = self.update.bind(self);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return modalComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return modalDefaults; }
    /* eslint-enable */

    // MODAL PUBLIC METHODS
    // ====================
    /** Toggles the visibility of the modal. */
    toggle() {
      const self = this;
      if (hasClass(self.element, showClass)) self.hide();
      else self.show();
    }

    /** Shows the modal to the user. */
    show() {
      const self = this;
      const {
        element, options, hasFade, relatedTarget, container,
      } = self;
      const { backdrop } = options;
      let overlayDelay = 0;

      if (hasClass(element, showClass)) return;

      showModalEvent.relatedTarget = relatedTarget || null;
      dispatchEvent(element, showModalEvent);
      if (showModalEvent.defaultPrevented) return;

      // we elegantly hide any opened modal/offcanvas
      const currentOpen = getCurrentOpen(element);
      if (currentOpen && currentOpen !== element) {
        const this1 = getModalInstance(currentOpen);
        const that1 = this1 || getInstance(currentOpen, 'Offcanvas');
        that1.hide();
      }

      if (backdrop) {
        if (!currentOpen && !hasClass(overlay, showClass)) {
          appendOverlay(container, hasFade, true);
        } else {
          toggleOverlayType(true);
        }
        overlayDelay = getElementTransitionDuration(overlay);

        if (!hasClass(overlay, showClass)) showOverlay();
        setTimeout(() => beforeModalShow(self), overlayDelay);
      } else {
        beforeModalShow(self);
        if (currentOpen && hasClass(overlay, showClass)) {
          hideOverlay();
        }
      }
    }

    /**
     * Hide the modal from the user.
     * @param {boolean=} force when `true` it will skip animation
     */
    hide(force) {
      const self = this;
      const {
        element, hasFade, relatedTarget,
      } = self;

      if (!hasClass(element, showClass)) return;

      hideModalEvent.relatedTarget = relatedTarget || null;
      dispatchEvent(element, hideModalEvent);
      if (hideModalEvent.defaultPrevented) return;
      removeClass(element, showClass);
      setAttribute(element, ariaHidden, 'true');
      removeAttribute(element, ariaModal);

      if (hasFade && force !== false) {
        emulateTransitionEnd(element, () => beforeModalHide(self));
      } else {
        beforeModalHide(self, force);
      }
    }

    /** Updates the modal layout. */
    update() {
      const self = this;

      if (hasClass(self.element, showClass)) setModalScrollbar(self);
    }

    /** Removes the `Modal` component from target element. */
    dispose() {
      const self = this;
      self.hide(true); // forced call

      toggleModalHandler(self);

      super.dispose();
    }
  }

  ObjectAssign(Modal, {
    selector: modalSelector,
    init: modalInitCallback,
    getInstance: getModalInstance,
  });

  /** @type {string} */
  const offcanvasComponent = 'Offcanvas';

  /* Native JavaScript for Bootstrap 5 | OffCanvas
  ------------------------------------------------ */

  // OFFCANVAS PRIVATE GC
  // ====================
  const offcanvasSelector = `.${offcanvasString}`;
  const offcanvasToggleSelector = `[${dataBsToggle}="${offcanvasString}"]`;
  const offcanvasDismissSelector = `[${dataBsDismiss}="${offcanvasString}"]`;
  const offcanvasTogglingClass = `${offcanvasString}-toggling`;

  const offcanvasDefaults = {
    backdrop: true, // boolean
    keyboard: true, // boolean
    scroll: false, // boolean
  };

  /**
   * Static method which returns an existing `Offcanvas` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Offcanvas>}
   */
  const getOffcanvasInstance = (element) => getInstance(element, offcanvasComponent);

  /**
   * An `Offcanvas` initialization callback.
   * @type {BSN.InitCallback<Offcanvas>}
   */
  const offcanvasInitCallback = (element) => new Offcanvas(element);

  // OFFCANVAS CUSTOM EVENTS
  // =======================
  const showOffcanvasEvent = OriginalEvent(`show.bs.${offcanvasString}`);
  const shownOffcanvasEvent = OriginalEvent(`shown.bs.${offcanvasString}`);
  const hideOffcanvasEvent = OriginalEvent(`hide.bs.${offcanvasString}`);
  const hiddenOffcanvasEvent = OriginalEvent(`hidden.bs.${offcanvasString}`);

  // OFFCANVAS PRIVATE METHODS
  // =========================
  /**
   * Sets additional style for the `<body>` and other elements
   * when showing an offcanvas to the user.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   */
  function setOffCanvasScrollbar(self) {
    const { element } = self;
    const { clientHeight, scrollHeight } = getDocumentElement(element);
    setScrollbar(element, clientHeight !== scrollHeight);
  }

  /**
   * Toggles on/off the `click` event listeners.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   * @param {boolean=} add when *true*, listeners are added
   */
  function toggleOffcanvasEvents(self, add) {
    const action = add ? addListener : removeListener;
    self.triggers.forEach((btn) => action(btn, mouseclickEvent, offcanvasTriggerHandler));
  }

  /**
   * Toggles on/off the listeners of the events that close the offcanvas.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   * @param {boolean=} add when *true* listeners are added
   */
  function toggleOffCanvasDismiss(self, add) {
    const action = add ? addListener : removeListener;
    const doc = getDocument(self.element);
    action(doc, keydownEvent, offcanvasKeyDismissHandler);
    action(doc, mouseclickEvent, offcanvasDismissHandler);
  }

  /**
   * Executes before showing the offcanvas.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   */
  function beforeOffcanvasShow(self) {
    const { element, options } = self;

    if (!options.scroll) {
      setOffCanvasScrollbar(self);
      getDocumentBody(element).style.overflow = 'hidden';
    }

    addClass(element, offcanvasTogglingClass);
    addClass(element, showClass);
    // @ts-ignore
    element.style.visibility = 'visible';

    emulateTransitionEnd(element, () => showOffcanvasComplete(self));
  }

  /**
   * Executes before hiding the offcanvas.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   */
  function beforeOffcanvasHide(self) {
    const { element, options } = self;
    const currentOpen = getCurrentOpen(element);

    // @ts-ignore
    element.blur();

    if (!currentOpen && options.backdrop && hasClass(overlay, showClass)) {
      hideOverlay();
      emulateTransitionEnd(overlay, () => hideOffcanvasComplete(self));
    } else hideOffcanvasComplete(self);
  }

  // OFFCANVAS EVENT HANDLERS
  // ========================
  /**
   * Handles the `click` event listeners.
   *
   * @this {HTMLElement | Element}
   * @param {MouseEvent} e the `Event` object
   */
  function offcanvasTriggerHandler(e) {
    const trigger = closest(this, offcanvasToggleSelector);
    const element = trigger && getTargetElement(trigger);
    const self = element && getOffcanvasInstance(element);

    if (self) {
      self.relatedTarget = trigger;
      self.toggle();
      if (trigger && trigger.tagName === 'A') {
        e.preventDefault();
      }
    }
  }

  /**
   * Handles the event listeners that close the offcanvas.
   *
   * @this {Document}
   * @param {MouseEvent} e the `Event` object
   */
  function offcanvasDismissHandler(e) {
    const element = querySelector(offcanvasActiveSelector, this);
    if (!element) return;

    const offCanvasDismiss = querySelector(offcanvasDismissSelector, element);
    const self = getOffcanvasInstance(element);

    if (!self) return;

    const { options, triggers } = self;
    const { target } = e;
    // @ts-ignore -- `EventTarget` is `HTMLElement`
    const trigger = closest(target, offcanvasToggleSelector);
    const selection = getDocument(element).getSelection();

    if (!(selection && selection.toString().length)
      // @ts-ignore
      && ((!element.contains(target) && options.backdrop
      && (!trigger || (trigger && !triggers.includes(trigger))))
      // @ts-ignore
      || (offCanvasDismiss && offCanvasDismiss.contains(target)))) {
      // @ts-ignore
      self.relatedTarget = offCanvasDismiss && offCanvasDismiss.contains(target)
        ? offCanvasDismiss : null;
      self.hide();
    }
    if (trigger && trigger.tagName === 'A') e.preventDefault();
  }

  /**
   * Handles the `keydown` event listener for offcanvas
   * to hide it when user type the `ESC` key.
   *
   * @param {KeyboardEvent} e the `Event` object
   * @this {Document}
   */
  function offcanvasKeyDismissHandler({ code }) {
    const element = querySelector(offcanvasActiveSelector, this);
    if (!element) return;

    const self = getOffcanvasInstance(element);

    if (self && self.options.keyboard && code === keyEscape) {
      self.relatedTarget = null;
      self.hide();
    }
  }

  /**
   * Handles the `transitionend` when showing the offcanvas.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   */
  function showOffcanvasComplete(self) {
    const { element, triggers } = self;
    removeClass(element, offcanvasTogglingClass);

    removeAttribute(element, ariaHidden);
    setAttribute(element, ariaModal, 'true');
    setAttribute(element, 'role', 'dialog');

    if (triggers.length) {
      triggers.forEach((btn) => setAttribute(btn, ariaExpanded, 'true'));
    }

    dispatchEvent(element, shownOffcanvasEvent);

    toggleOffCanvasDismiss(self, true);
    focus(element);
  }

  /**
   * Handles the `transitionend` when hiding the offcanvas.
   *
   * @param {Offcanvas} self the `Offcanvas` instance
   */
  function hideOffcanvasComplete(self) {
    const { element, triggers } = self;

    setAttribute(element, ariaHidden, 'true');
    removeAttribute(element, ariaModal);
    removeAttribute(element, 'role');
    // @ts-ignore
    element.style.visibility = '';

    if (triggers.length) {
      triggers.forEach((btn) => setAttribute(btn, ariaExpanded, 'false'));
      const visibleTrigger = triggers.find((x) => isVisible(x));
      if (visibleTrigger) focus(visibleTrigger);
    }

    removeOverlay(element);

    dispatchEvent(element, hiddenOffcanvasEvent);
    removeClass(element, offcanvasTogglingClass);

    // must check for open instances
    if (!getCurrentOpen(element)) {
      toggleOffCanvasDismiss(self);
    }
  }

  // OFFCANVAS DEFINITION
  // ====================
  /** Returns a new `Offcanvas` instance. */
  class Offcanvas extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target usually an `.offcanvas` element
     * @param {BSN.Options.Offcanvas=} config instance options
     */
    constructor(target, config) {
      super(target, config);
      const self = this;

      // instance element
      const { element } = self;

      // all the triggering buttons
      /** @type {(HTMLElement | Element)[]} */
      self.triggers = [...querySelectorAll(offcanvasToggleSelector)]
        .filter((btn) => getTargetElement(btn) === element);

      // additional instance property
      /** @type {HTMLBodyElement | HTMLElement | Element} */
      // @ts-ignore
      self.container = getElementContainer(element);
      /** @type {(HTMLElement | Element)?} */
      self.relatedTarget = null;

      // attach event listeners
      toggleOffcanvasEvents(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return offcanvasComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return offcanvasDefaults; }
    /* eslint-enable */

    // OFFCANVAS PUBLIC METHODS
    // ========================
    /** Shows or hides the offcanvas from the user. */
    toggle() {
      const self = this;
      if (hasClass(self.element, showClass)) self.hide();
      else self.show();
    }

    /** Shows the offcanvas to the user. */
    show() {
      const self = this;
      const {
        element, options, container, relatedTarget,
      } = self;
      let overlayDelay = 0;

      if (hasClass(element, showClass)) return;

      showOffcanvasEvent.relatedTarget = relatedTarget;
      shownOffcanvasEvent.relatedTarget = relatedTarget;
      dispatchEvent(element, showOffcanvasEvent);
      if (showOffcanvasEvent.defaultPrevented) return;

      // we elegantly hide any opened modal/offcanvas
      const currentOpen = getCurrentOpen(element);
      if (currentOpen && currentOpen !== element) {
        const this1 = getOffcanvasInstance(currentOpen);
        const that1 = this1 || getInstance(currentOpen, 'Modal');
        that1.hide();
      }

      if (options.backdrop) {
        if (!currentOpen) {
          appendOverlay(container, true);
        } else {
          toggleOverlayType();
        }
        overlayDelay = getElementTransitionDuration(overlay);
        if (!hasClass(overlay, showClass)) showOverlay();

        setTimeout(() => beforeOffcanvasShow(self), overlayDelay);
      } else {
        beforeOffcanvasShow(self);
        if (currentOpen && hasClass(overlay, showClass)) {
          hideOverlay();
        }
      }
    }

    /**
     * Hides the offcanvas from the user.
     * @param {boolean=} force when `true` it will skip animation
     */
    hide(force) {
      const self = this;
      const { element, relatedTarget } = self;

      if (!hasClass(element, showClass)) return;

      hideOffcanvasEvent.relatedTarget = relatedTarget;
      hiddenOffcanvasEvent.relatedTarget = relatedTarget;
      dispatchEvent(element, hideOffcanvasEvent);
      if (hideOffcanvasEvent.defaultPrevented) return;

      addClass(element, offcanvasTogglingClass);
      removeClass(element, showClass);

      if (!force) {
        emulateTransitionEnd(element, () => beforeOffcanvasHide(self));
      } else beforeOffcanvasHide(self);
    }

    /** Removes the `Offcanvas` from the target element. */
    dispose() {
      const self = this;
      self.hide(true);
      toggleOffcanvasEvents(self);
      super.dispose();
    }
  }

  ObjectAssign(Offcanvas, {
    selector: offcanvasSelector,
    init: offcanvasInitCallback,
    getInstance: getOffcanvasInstance,
  });

  /** @type {string} */
  const popoverString = 'popover';

  /** @type {string} */
  const popoverComponent = 'Popover';

  /** @type {string} */
  const tooltipString = 'tooltip';

  /**
   * Returns a template for Popover / Tooltip.
   *
   * @param {string} tipType the expected markup type
   * @returns {string} the template markup
   */
  function getTipTemplate(tipType) {
    const isTooltip = tipType === tooltipString;
    const bodyClass = isTooltip ? `${tipType}-inner` : `${tipType}-body`;
    const header = !isTooltip ? `<h3 class="${tipType}-header"></h3>` : '';
    const arrow = `<div class="${tipType}-arrow"></div>`;
    const body = `<div class="${bodyClass}"></div>`;
    return `<div class="${tipType}" role="${tooltipString}">${header + arrow + body}</div>`;
  }

  /**
   * Checks if an element is an `<svg>` (or any type of SVG element),
   * `<img>` or `<video>`.
   *
   * *Tooltip* / *Popover* works different with media elements.
   * @param {any} element the target element
   * @returns {boolean} the query result
   */
  const isMedia = (element) => element
    && [SVGElement, HTMLImageElement, HTMLVideoElement]
      .some((mediaType) => element instanceof mediaType);

  /**
   * Returns an `{x,y}` object with the target
   * `HTMLElement` / `Node` scroll position.
   *
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {HTMLElement | Element | Window} element target node / element
   * @returns {{x: number, y: number}} the scroll tuple
   */
  function getNodeScroll(element) {
    const isWin = 'scrollX' in element;
    const x = isWin ? element.scrollX : element.scrollLeft;
    const y = isWin ? element.scrollY : element.scrollTop;

    return { x, y };
  }

  /**
   * Checks if a target `HTMLElement` is affected by scale.
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {HTMLElement} element target
   * @returns {boolean} the query result
   */
  function isScaledElement(element) {
    const { width, height } = getBoundingClientRect(element);
    const { offsetWidth, offsetHeight } = element;
    return Math.round(width) !== offsetWidth
      || Math.round(height) !== offsetHeight;
  }

  /**
   * Returns the rect relative to an offset parent.
   * @see https://github.com/floating-ui/floating-ui
   *
   * @param {HTMLElement | Element} element target
   * @param {HTMLElement | Element | Window} offsetParent the container / offset parent
   * @param {{x: number, y: number}} scroll
   * @returns {SHORTER.OffsetRect}
   */
  function getRectRelativeToOffsetParent(element, offsetParent, scroll) {
    const isParentAnElement = offsetParent instanceof HTMLElement;
    const rect = getBoundingClientRect(element, isParentAnElement && isScaledElement(offsetParent));
    const offsets = { x: 0, y: 0 };

    if (isParentAnElement) {
      const offsetRect = getBoundingClientRect(offsetParent, true);
      offsets.x = offsetRect.x + offsetParent.clientLeft;
      offsets.y = offsetRect.y + offsetParent.clientTop;
    }

    return {
      x: rect.left + scroll.x - offsets.x,
      y: rect.top + scroll.y - offsets.y,
      width: rect.width,
      height: rect.height,
    };
  }

  /** @type {Record<string, string>} */
  var tipClassPositions = {
    top: 'top',
    bottom: 'bottom',
    left: 'start',
    right: 'end',
  };

  /**
   * Style popovers and tooltips.
   * @param {BSN.Tooltip | BSN.Popover} self the `Popover` / `Tooltip` instance
   * @param {PointerEvent=} e event object
   */
  function styleTip(self, e) {
    const tipClasses = /\b(top|bottom|start|end)+/;
    const {
      element, tooltip, options, arrow, offsetParent,
    } = self;
    const tipPositions = { ...tipClassPositions };

    // reset tooltip style (top: 0, left: 0 works best)
    setElementStyle(tooltip, { top: '0px', left: '0px', right: '' });
    // @ts-ignore
    const isPopover = self.name === popoverComponent;
    const tipWidth = tooltip.offsetWidth;
    const tipHeight = tooltip.offsetHeight;
    const RTL = isRTL(element);
    if (RTL) {
      tipPositions.left = 'end';
      tipPositions.right = 'start';
    }
    const documentElement = getDocumentElement(element);
    const windowWidth = documentElement.clientWidth;
    const windowHeight = documentElement.clientHeight;
    const { container } = options;
    let { placement } = options;
    const {
      left: parentLeft, right: parentRight, top: parentTop,
    } = getBoundingClientRect(container, true);
    const parentWidth = container.clientWidth;
    const scrollbarWidth = Math.abs(parentWidth - container.offsetWidth);
    const parentPosition = getElementStyle(container, 'position');
    // const absoluteParent = parentPosition === 'absolute';
    const fixedParent = parentPosition === 'fixed';
    const staticParent = parentPosition === 'static';
    const stickyParent = parentPosition === 'sticky';
    const isSticky = stickyParent && parentTop === parseFloat(getElementStyle(container, 'top'));
    // const absoluteTarget = getElementStyle(element, 'position') === 'absolute';
    // const stickyFixedParent = ['sticky', 'fixed'].includes(parentPosition);
    const leftBoundry = RTL && fixedParent ? scrollbarWidth : 0;
    const rightBoundry = fixedParent ? parentWidth + parentLeft + (RTL ? scrollbarWidth : 0)
      : parentWidth + parentLeft + (windowWidth - parentRight) - 1;
    const {
      width: elemWidth,
      height: elemHeight,
      left: elemRectLeft,
      right: elemRectRight,
      top: elemRectTop,
    } = getBoundingClientRect(element, true);

    const scroll = getNodeScroll(offsetParent);
    const { x, y } = getRectRelativeToOffsetParent(element, offsetParent, scroll);
    // reset arrow style
    setElementStyle(arrow, { top: '', left: '', right: '' });
    let topPosition;
    let leftPosition;
    let rightPosition;
    let arrowTop;
    let arrowLeft;
    let arrowRight;

    const arrowWidth = arrow.offsetWidth || 0;
    const arrowHeight = arrow.offsetHeight || 0;
    const arrowAdjust = arrowWidth / 2;

    // check placement
    let topExceed = elemRectTop - tipHeight - arrowHeight < 0;
    let bottomExceed = elemRectTop + tipHeight + elemHeight
      + arrowHeight >= windowHeight;
    let leftExceed = elemRectLeft - tipWidth - arrowWidth < leftBoundry;
    let rightExceed = elemRectLeft + tipWidth + elemWidth
      + arrowWidth >= rightBoundry;

    const horizontal = ['left', 'right'];
    const vertical = ['top', 'bottom'];
    topExceed = horizontal.includes(placement)
      ? elemRectTop + elemHeight / 2 - tipHeight / 2 - arrowHeight < 0
      : topExceed;
    bottomExceed = horizontal.includes(placement)
      ? elemRectTop + tipHeight / 2 + elemHeight / 2 + arrowHeight >= windowHeight
      : bottomExceed;
    leftExceed = vertical.includes(placement)
      ? elemRectLeft + elemWidth / 2 - tipWidth / 2 < leftBoundry
      : leftExceed;
    rightExceed = vertical.includes(placement)
      ? elemRectLeft + tipWidth / 2 + elemWidth / 2 >= rightBoundry
      : rightExceed;

    // recompute placement
    // first, when both left and right limits are exceeded, we fall back to top|bottom
    placement = (horizontal.includes(placement)) && leftExceed && rightExceed ? 'top' : placement;
    placement = placement === 'top' && topExceed ? 'bottom' : placement;
    placement = placement === 'bottom' && bottomExceed ? 'top' : placement;
    placement = placement === 'left' && leftExceed ? 'right' : placement;
    placement = placement === 'right' && rightExceed ? 'left' : placement;

    // update tooltip/popover class
    if (!tooltip.className.includes(placement)) {
      tooltip.className = tooltip.className.replace(tipClasses, tipPositions[placement]);
    }

    // compute tooltip / popover coordinates
    if (horizontal.includes(placement)) { // secondary|side positions
      if (placement === 'left') { // LEFT
        leftPosition = x - tipWidth - (isPopover ? arrowWidth : 0);
      } else { // RIGHT
        leftPosition = x + elemWidth + (isPopover ? arrowWidth : 0);
      }

      // adjust top and arrow
      if (topExceed) {
        topPosition = y;
        topPosition += (isSticky ? -parentTop - scroll.y : 0);

        arrowTop = elemHeight / 2 - arrowWidth;
      } else if (bottomExceed) {
        topPosition = y - tipHeight + elemHeight;
        topPosition += (isSticky ? -parentTop - scroll.y : 0);

        arrowTop = tipHeight - elemHeight / 2 - arrowWidth;
      } else {
        topPosition = y - tipHeight / 2 + elemHeight / 2;
        topPosition += (isSticky ? -parentTop - scroll.y : 0);

        arrowTop = tipHeight / 2 - arrowHeight / 2;
      }
    } else if (vertical.includes(placement)) {
      if (e && isMedia(element)) {
        let eX = 0;
        let eY = 0;
        if (staticParent) {
          eX = e.pageX;
          eY = e.pageY;
        } else { // fixedParent | stickyParent
          eX = e.clientX - parentLeft + (fixedParent ? scroll.x : 0);
          eY = e.clientY - parentTop + (fixedParent ? scroll.y : 0);
        }

        // some weird RTL bug
        eX -= RTL && fixedParent && scrollbarWidth ? scrollbarWidth : 0;

        if (placement === 'top') {
          topPosition = eY - tipHeight - arrowWidth;
        } else {
          topPosition = eY + arrowWidth;
        }

        // adjust (left | right) and also the arrow
        if (e.clientX - tipWidth / 2 < leftBoundry) {
          leftPosition = 0;
          arrowLeft = eX - arrowAdjust;
        } else if (e.clientX + tipWidth / 2 > rightBoundry) {
          leftPosition = 'auto';
          rightPosition = 0;
          arrowRight = rightBoundry - eX - arrowAdjust;
          arrowRight -= fixedParent ? parentLeft + (RTL ? scrollbarWidth : 0) : 0;

        // normal top/bottom
        } else {
          leftPosition = eX - tipWidth / 2;
          arrowLeft = tipWidth / 2 - arrowAdjust;
        }
      } else {
        if (placement === 'top') {
          topPosition = y - tipHeight - (isPopover ? arrowHeight : 0);
        } else { // BOTTOM
          topPosition = y + elemHeight + (isPopover ? arrowHeight : 0);
        }

        // adjust left | right and also the arrow
        if (leftExceed) {
          leftPosition = 0;
          arrowLeft = x + elemWidth / 2 - arrowAdjust;
        } else if (rightExceed) {
          leftPosition = 'auto';
          rightPosition = 0;
          arrowRight = elemWidth / 2 + rightBoundry - elemRectRight - arrowAdjust;
        } else {
          leftPosition = x - tipWidth / 2 + elemWidth / 2;
          arrowLeft = tipWidth / 2 - arrowAdjust;
        }
      }
    }

    // apply style to tooltip/popover
    setElementStyle(tooltip, {
      top: `${topPosition}px`,
      left: leftPosition === 'auto' ? leftPosition : `${leftPosition}px`,
      right: rightPosition !== undefined ? `${rightPosition}px` : '',
    });

    // update arrow placement
    if (arrow instanceof HTMLElement) {
      if (arrowTop !== undefined) {
        arrow.style.top = `${arrowTop}px`;
      }
      if (arrowLeft !== undefined) {
        arrow.style.left = `${arrowLeft}px`;
      } else if (arrowRight !== undefined) {
        arrow.style.right = `${arrowRight}px`;
      }
    }
  }

  const tooltipDefaults = {
    /** @type {string} */
    template: getTipTemplate(tooltipString),
    /** @type {string?} */
    title: null, // string
    /** @type {string?} */
    customClass: null, // string | null
    /** @type {string} */
    trigger: 'hover focus',
    /** @type {string?} */
    placement: 'top', // string
    /** @type {((c:string)=>string)?} */
    sanitizeFn: null, // function
    /** @type {boolean} */
    animation: true, // bool
    /** @type {number} */
    delay: 200, // number
    /** @type {(HTMLElement | Element)?} */
    container: null,
  };

  /**
   * A global namespace for aria-describedby.
   * @type {string}
   */
  const ariaDescribedBy = 'aria-describedby';

  /**
   * A global namespace for `mousedown` event.
   * @type {string}
   */
  const mousedownEvent = 'mousedown';

  /**
   * A global namespace for `mousemove` event.
   * @type {string}
   */
  const mousemoveEvent = 'mousemove';

  /**
   * A global namespace for `focusin` event.
   * @type {string}
   */
  const focusinEvent = 'focusin';

  /**
   * A global namespace for `focusout` event.
   * @type {string}
   */
  const focusoutEvent = 'focusout';

  /**
   * A global namespace for `hover` event.
   * @type {string}
   */
  const mousehoverEvent = 'hover';

  let elementUID = 1;
  const elementIDMap = new Map();

  /**
   * Returns a unique identifier for popover, tooltip, scrollspy.
   *
   * @param {HTMLElement | Element} element target element
   * @param {string=} key predefined key
   * @returns {number} an existing or new unique ID
   */
  function getUID(element, key) {
    elementUID += 1;
    let elMap = elementIDMap.get(element);
    let result = elementUID;

    if (key && key.length) {
      if (elMap) {
        const elMapId = elMap.get(key);
        if (!Number.isNaN(elMapId)) {
          result = elMapId;
        } else {
          elMap.set(key, result);
        }
      } else {
        elementIDMap.set(element, new Map());
        elMap = elementIDMap.get(element);
        elMap.set(key, result);
      }
    } else if (!Number.isNaN(elMap)) {
      result = elMap;
    } else {
      elementIDMap.set(element, result);
    }
    return result;
  }

  // @ts-ignore
  const { userAgentData: uaDATA } = navigator;

  /**
   * A global namespace for `userAgentData` object.
   */
  const userAgentData = uaDATA;

  const { userAgent: userAgentString } = navigator;

  /**
   * A global namespace for `navigator.userAgent` string.
   */
  const userAgent = userAgentString;

  const appleBrands = /(iPhone|iPod|iPad)/;

  /**
   * A global `boolean` for Apple browsers.
   * @type {boolean}
   */
  const isApple = !userAgentData ? appleBrands.test(userAgent)
    : userAgentData.brands.some((/** @type {Record<string, any>} */x) => appleBrands.test(x.brand));

  /**
   * Global namespace for `data-bs-title` attribute.
   */
  const dataOriginalTitle = 'data-original-title';

  /** @type {string} */
  const tooltipComponent = 'Tooltip';

  /**
   * Append an existing `Element` to Popover / Tooltip component or HTML
   * markup string to be parsed & sanitized to be used as popover / tooltip content.
   *
   * @param {HTMLElement | Element} element target
   * @param {HTMLElement | Element | string} content the `Element` to append / string
   * @param {ReturnType<any>} sanitizeFn a function to sanitize string content
   */
  function setHtml(element, content, sanitizeFn) {
    if (typeof content === 'string' && !content.length) return;

    if (typeof content === 'string') {
      let dirty = content.trim(); // fixing #233
      if (typeof sanitizeFn === 'function') dirty = sanitizeFn(dirty);

      const domParser = new DOMParser();
      const tempDocument = domParser.parseFromString(dirty, 'text/html');
      const { body } = tempDocument;
      const method = body.children.length ? 'innerHTML' : 'innerText';
      // @ts-ignore
      element[method] = body[method];
    } else if (content instanceof HTMLElement) {
      element.append(content);
    }
  }

  /**
   * Creates a new tooltip / popover.
   *
   * @param {BSN.Popover | BSN.Tooltip} self the `Popover` instance
   */
  function createTip(self) {
    const { id, element, options } = self;
    const {
      animation, customClass, sanitizeFn, placement, dismissible,
    } = options;
    let { title, content } = options;
    const isTooltip = self.name === tooltipComponent;
    const tipString = isTooltip ? tooltipString : popoverString;
    const { template, btnClose } = options;
    const tipPositions = { ...tipClassPositions };

    if (isRTL(element)) {
      tipPositions.left = 'end';
      tipPositions.right = 'start';
    }

    // set initial popover class
    const placementClass = `bs-${tipString}-${tipPositions[placement]}`;

    // load template
    /** @type {(HTMLElement | Element)?} */
    let popoverTemplate;
    if ([Element, HTMLElement].some((x) => template instanceof x)) {
      popoverTemplate = template;
    } else {
      const htmlMarkup = getDocument(element).createElement('div');
      setHtml(htmlMarkup, template, sanitizeFn);
      popoverTemplate = htmlMarkup.firstElementChild;
    }

    // set popover markup
    self.tooltip = popoverTemplate && popoverTemplate.cloneNode(true);

    const { tooltip } = self;

    // set id and role attributes
    setAttribute(tooltip, 'id', id);
    setAttribute(tooltip, 'role', tooltipString);

    const bodyClass = isTooltip ? `${tooltipString}-inner` : `${popoverString}-body`;
    const tooltipHeader = isTooltip ? null : querySelector(`.${popoverString}-header`, tooltip);
    const tooltipBody = querySelector(`.${bodyClass}`, tooltip);

    // set arrow and enable access for styleTip
    self.arrow = querySelector(`.${tipString}-arrow`, tooltip);

    // set dismissible button
    if (dismissible) {
      if (title) {
        if (title instanceof HTMLElement) setHtml(title, btnClose, sanitizeFn);
        else title += btnClose;
      } else {
        if (tooltipHeader) tooltipHeader.remove();
        if (content instanceof HTMLElement) setHtml(content, btnClose, sanitizeFn);
        else content += btnClose;
      }
    }

    // fill the template with content from options / data attributes
    // also sanitize title && content
    if (!isTooltip) {
      if (title && tooltipHeader) setHtml(tooltipHeader, title, sanitizeFn);
      if (content && tooltipBody) setHtml(tooltipBody, content, sanitizeFn);
      // @ts-ignore -- set btn
      self.btn = querySelector('.btn-close', tooltip);
    } else if (title && tooltipBody) setHtml(tooltipBody, title, sanitizeFn);

    // set popover animation and placement
    if (!hasClass(tooltip, tipString)) addClass(tooltip, tipString);
    if (animation && !hasClass(tooltip, fadeClass)) addClass(tooltip, fadeClass);
    if (customClass && !hasClass(tooltip, customClass)) {
      addClass(tooltip, customClass);
    }
    if (!hasClass(tooltip, placementClass)) addClass(tooltip, placementClass);
  }

  /**
   * @param {(HTMLElement | Element)?} tip target
   * @param {HTMLElement | ParentNode} container parent container
   * @returns {boolean}
   */
  function isVisibleTip(tip, container) {
    return tip instanceof HTMLElement && container.contains(tip);
  }

  /* Native JavaScript for Bootstrap 5 | Tooltip
  ---------------------------------------------- */

  // TOOLTIP PRIVATE GC
  // ==================
  const tooltipSelector = `[${dataBsToggle}="${tooltipString}"],[data-tip="${tooltipString}"]`;
  const titleAttr = 'title';

  /**
   * Static method which returns an existing `Tooltip` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Tooltip>}
   */
  let getTooltipInstance = (element) => getInstance(element, tooltipComponent);

  /**
   * A `Tooltip` initialization callback.
   * @type {BSN.InitCallback<Tooltip>}
   */
  const tooltipInitCallback = (element) => new Tooltip(element);

  // TOOLTIP PRIVATE METHODS
  // =======================
  /**
   * Removes the tooltip from the DOM.
   *
   * @param {Tooltip} self the `Tooltip` instance
   */
  function removeTooltip(self) {
    const { element, tooltip } = self;
    removeAttribute(element, ariaDescribedBy);
    tooltip.remove();
  }

  /**
   * Executes after the instance has been disposed.
   *
   * @param {Tooltip} self the `Tooltip` instance
   */
  function disposeTooltipComplete(self) {
    const { element } = self;
    toggleTooltipHandlers(self);

    if (element.hasAttribute(dataOriginalTitle) && self.name === tooltipString) {
      toggleTooltipTitle(self);
    }
  }

  /**
   * Toggles on/off the special `Tooltip` event listeners.
   *
   * @param {Tooltip} self the `Tooltip` instance
   * @param {boolean=} add when `true`, event listeners are added
   */
  function toggleTooltipAction(self, add) {
    const action = add ? addListener : removeListener;
    const { element } = self;

    action(getDocument(element), touchstartEvent, self.handleTouch, passiveHandler);

    if (!isMedia(element)) {
      [scrollEvent, resizeEvent].forEach((ev) => {
        // @ts-ignore
        action(getWindow(element), ev, self.update, passiveHandler);
      });
    }
  }

  /**
   * Executes after the tooltip was shown to the user.
   *
   * @param {Tooltip} self the `Tooltip` instance
   */
  function tooltipShownAction(self) {
    const { element } = self;
    const shownTooltipEvent = OriginalEvent(`shown.bs.${toLowerCase(self.name)}`);

    toggleTooltipAction(self, true);
    dispatchEvent(element, shownTooltipEvent);
    Timer.clear(element, 'in');
  }

  /**
   * Executes after the tooltip was hidden to the user.
   *
   * @param {Tooltip} self the `Tooltip` instance
   */
  function tooltipHiddenAction(self) {
    const { element } = self;
    const hiddenTooltipEvent = OriginalEvent(`hidden.bs.${toLowerCase(self.name)}`);

    toggleTooltipAction(self);
    removeTooltip(self);
    dispatchEvent(element, hiddenTooltipEvent);
    Timer.clear(element, 'out');
  }

  /**
   * Toggles on/off the `Tooltip` event listeners.
   *
   * @param {Tooltip} self the `Tooltip` instance
   * @param {boolean=} add when `true`, event listeners are added
   */
  function toggleTooltipHandlers(self, add) {
    const action = add ? addListener : removeListener;
    // @ts-ignore -- btn is only for dismissible popover
    const { element, options, btn } = self;
    const { trigger, dismissible } = options;

    if (trigger.includes('manual')) return;

    self.enabled = !!add;

    /** @type {string[]} */
    const triggerOptions = trigger.split(' ');
    const elemIsMedia = isMedia(element);

    if (elemIsMedia) {
      action(element, mousemoveEvent, self.update, passiveHandler);
    }

    triggerOptions.forEach((tr) => {
      if (elemIsMedia || tr === mousehoverEvent) {
        action(element, mousedownEvent, self.show);
        action(element, mouseenterEvent, self.show);

        if (dismissible && btn) {
          action(btn, mouseclickEvent, self.hide);
        } else {
          action(element, mouseleaveEvent, self.hide);
          action(getDocument(element), touchstartEvent, self.handleTouch, passiveHandler);
        }
      } else if (tr === mouseclickEvent) {
        action(element, tr, (!dismissible ? self.toggle : self.show));
      } else if (tr === focusEvent) {
        action(element, focusinEvent, self.show);
        if (!dismissible) action(element, focusoutEvent, self.hide);
        if (isApple) action(element, mouseclickEvent, () => focus(element));
      }
    });
  }

  /**
   * Toggles on/off the `Tooltip` event listeners that hide/update the tooltip.
   *
   * @param {Tooltip} self the `Tooltip` instance
   * @param {boolean=} add when `true`, event listeners are added
   */
  function toggleTooltipOpenHandlers(self, add) {
    const action = add ? addListener : removeListener;
    const { element, options, offsetParent } = self;
    const { container } = options;
    const { offsetHeight, scrollHeight } = container;
    const parentModal = closest(element, `.${modalString}`);
    const parentOffcanvas = closest(element, `.${offcanvasString}`);

    if (!isMedia(element)) {
      const win = getWindow(element);
      const overflow = offsetHeight !== scrollHeight;
      const scrollTarget = overflow || offsetParent !== win ? container : win;
      // @ts-ignore
      action(win, resizeEvent, self.update, passiveHandler);
      action(scrollTarget, scrollEvent, self.update, passiveHandler);
    }

    // dismiss tooltips inside modal / offcanvas
    if (parentModal) action(parentModal, `hide.bs.${modalString}`, self.hide);
    if (parentOffcanvas) action(parentOffcanvas, `hide.bs.${offcanvasString}`, self.hide);
  }

  /**
   * Toggles the `title` and `data-original-title` attributes.
   *
   * @param {Tooltip} self the `Tooltip` instance
   * @param {string=} content when `true`, event listeners are added
   */
  function toggleTooltipTitle(self, content) {
    // [0 - add, 1 - remove] | [0 - remove, 1 - add]
    const titleAtt = [dataOriginalTitle, titleAttr];
    const { element } = self;

    setAttribute(element, titleAtt[content ? 0 : 1],
      // @ts-ignore
      (content || getAttribute(element, titleAtt[0])));
    removeAttribute(element, titleAtt[content ? 1 : 0]);
  }

  // TOOLTIP DEFINITION
  // ==================
  /** Creates a new `Tooltip` instance. */
  class Tooltip extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target the target element
     * @param {BSN.Options.Tooltip=} config the instance options
     */
    constructor(target, config) {
      super(target, config);

      // bind
      const self = this;
      const { element } = self;
      const isTooltip = self.name === tooltipComponent;
      const tipString = isTooltip ? tooltipString : popoverString;
      const tipComponent = isTooltip ? tooltipComponent : popoverComponent;

      getTooltipInstance = (elem) => getInstance(elem, tipComponent);

      // additional properties
      /** @type {any} */
      self.tooltip = {};
      if (!isTooltip) {
        /** @type {any?} */
        // @ts-ignore
        self.btn = null;
      }
      /** @type {any} */
      self.arrow = {};
      /** @type {any} */
      self.offsetParent = {};
      /** @type {boolean} */
      self.enabled = true;
      /** @type {string} Set unique ID for `aria-describedby`. */
      self.id = `${tipString}-${getUID(element, tipString)}`;

      // instance options
      const { options } = self;

      // invalidate
      if ((!options.title && isTooltip) || (!isTooltip && !options.content)) return;

      const container = querySelector(options.container);
      const idealContainer = getElementContainer(element);

      // bypass container option when its position is static/relative
      self.options.container = !container || (container
        && ['static', 'relative'].includes(getElementStyle(container, 'position')))
        ? idealContainer
        : container || getDocumentBody(element);

      // reset default options
      tooltipDefaults[titleAttr] = null;

      // all functions bind
      self.handleTouch = self.handleTouch.bind(self);
      self.update = self.update.bind(self);
      self.show = self.show.bind(self);
      self.hide = self.hide.bind(self);
      self.toggle = self.toggle.bind(self);

      // set title attributes and add event listeners
      if (element.hasAttribute(titleAttr) && isTooltip) {
        toggleTooltipTitle(self, options.title);
      }

      // create tooltip here
      createTip(self);

      // attach events
      toggleTooltipHandlers(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return tooltipComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return tooltipDefaults; }
    /* eslint-enable */

    // TOOLTIP PUBLIC METHODS
    // ======================
    /**
     * Shows the tooltip.
     *
     * @param {Event=} e the `Event` object
     * @this {Tooltip}
     */
    show(e) {
      const self = this;
      const {
        options, tooltip, element, id,
      } = self;
      const { container, animation } = options;
      const outTimer = Timer.get(element, 'out');

      Timer.clear(element, 'out');

      if (tooltip && !outTimer && !isVisibleTip(tooltip, container)) {
        Timer.set(element, () => {
          const showTooltipEvent = OriginalEvent(`show.bs.${toLowerCase(self.name)}`);
          dispatchEvent(element, showTooltipEvent);
          if (showTooltipEvent.defaultPrevented) return;

          // append to container
          container.append(tooltip);
          setAttribute(element, ariaDescribedBy, `#${id}`);
          // set offsetParent
          self.offsetParent = getElementContainer(tooltip, true);

          self.update(e);
          toggleTooltipOpenHandlers(self, true);

          if (!hasClass(tooltip, showClass)) addClass(tooltip, showClass);
          if (animation) emulateTransitionEnd(tooltip, () => tooltipShownAction(self));
          else tooltipShownAction(self);
        }, 17, 'in');
      }
    }

    /**
     * Hides the tooltip.
     *
     * @this {Tooltip}
     */
    hide() {
      const self = this;
      const { options, tooltip, element } = self;
      const { container, animation, delay } = options;

      Timer.clear(element, 'in');

      if (tooltip && isVisibleTip(tooltip, container)) {
        Timer.set(element, () => {
          const hideTooltipEvent = OriginalEvent(`hide.bs.${toLowerCase(self.name)}`);
          dispatchEvent(element, hideTooltipEvent);

          if (hideTooltipEvent.defaultPrevented) return;

          // @ts-ignore
          removeClass(tooltip, showClass);
          toggleTooltipOpenHandlers(self);

          if (animation) emulateTransitionEnd(tooltip, () => tooltipHiddenAction(self));
          else tooltipHiddenAction(self);
        }, delay + 17, 'out');
      }
    }

    /**
     * Updates the tooltip position.
     *
     * @param {Event=} e the `Event` object
     * @this {Tooltip} the `Tooltip` instance
     */
    update(e) {
      // @ts-ignore
      styleTip(this, e);
    }

    /**
     * Toggles the tooltip visibility.
     *
     * @param {Event=} e the `Event` object
     * @this {Tooltip} the instance
     */
    toggle(e) {
      const self = this;
      const { tooltip, options } = self;

      if (!isVisibleTip(tooltip, options.container)) self.show(e);
      else self.hide();
    }

    /** Enables the tooltip. */
    enable() {
      const self = this;
      const { enabled } = self;
      if (!enabled) {
        toggleTooltipHandlers(self, true);
        self.enabled = !enabled;
      }
    }

    /** Disables the tooltip. */
    disable() {
      const self = this;
      const {
        element, tooltip, options, enabled,
      } = self;
      const { animation, container, delay } = options;
      if (enabled) {
        if (isVisibleTip(tooltip, container) && animation) {
          self.hide();

          Timer.set(element, () => {
            toggleTooltipHandlers(self);
            Timer.clear(element, tooltipString);
          }, getElementTransitionDuration(tooltip) + delay + 17, tooltipString);
        } else {
          toggleTooltipHandlers(self);
        }
        self.enabled = !enabled;
      }
    }

    /** Toggles the `disabled` property. */
    toggleEnabled() {
      const self = this;
      if (!self.enabled) self.enable();
      else self.disable();
    }

    /**
     * Handles the `touchstart` event listener for `Tooltip`
     * @this {Tooltip}
     * @param {TouchEvent} e the `Event` object
     */
    handleTouch({ target }) {
      const { tooltip, element } = this;

      if (tooltip.contains(target) || target === element
        // @ts-ignore
        || (target && element.contains(target))) ; else {
        this.hide();
      }
    }

    /** Removes the `Tooltip` from the target element. */
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
      super.dispose();
    }
  }

  ObjectAssign(Tooltip, {
    selector: tooltipSelector,
    init: tooltipInitCallback,
    getInstance: getTooltipInstance,
    styleTip,
  });

  /* Native JavaScript for Bootstrap 5 | Popover
  ---------------------------------------------- */

  // POPOVER PRIVATE GC
  // ==================
  const popoverSelector = `[${dataBsToggle}="${popoverString}"],[data-tip="${popoverString}"]`;

  const popoverDefaults = {
    ...tooltipDefaults,
    /** @type {string} */
    template: getTipTemplate(popoverString),
    /** @type {string} */
    btnClose: '<button class="btn-close" aria-label="Close"></button>',
    /** @type {boolean} */
    dismissible: false,
    /** @type {string?} */
    content: null,
  };

  // POPOVER DEFINITION
  // ==================
  /** Returns a new `Popover` instance. */
  class Popover extends Tooltip {
    /* eslint-disable -- we want to specify Popover Options */
    /**
     * @param {HTMLElement | Element | string} target the target element
     * @param {BSN.Options.Popover=} config the instance options
     */
    constructor(target, config) {
      super(target, config);
    }
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return popoverComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return popoverDefaults; }
    /* eslint-enable */

    /* extend original `show()` */
    show() {
      super.show();
      // @ts-ignore -- btn only exists within dismissible popover
      const { options, btn } = this;
      if (options.dismissible && btn) setTimeout(() => focus(btn), 17);
    }
  }

  /**
   * Static method which returns an existing `Popover` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Popover>}
   */
  const getPopoverInstance = (element) => getInstance(element, popoverComponent);

  /**
   * A `Popover` initialization callback.
   * @type {BSN.InitCallback<Popover>}
   */
  const popoverInitCallback = (element) => new Popover(element);

  ObjectAssign(Popover, {
    selector: popoverSelector,
    init: popoverInitCallback,
    getInstance: getPopoverInstance,
    styleTip,
  });

  /**
   * Shortcut for `HTMLElement.getElementsByTagName` method. Some `Node` elements
   * like `ShadowRoot` do not support `getElementsByTagName`.
   *
   * @param {string} selector the tag name
   * @param {(HTMLElement | Element | Document)=} parent optional Element to look into
   * @return {HTMLCollectionOf<HTMLElement | Element>} the 'HTMLCollection'
   */
  function getElementsByTagName(selector, parent) {
    const lookUp = parent && parentNodes
      .some((x) => parent instanceof x) ? parent : getDocument();
    return lookUp.getElementsByTagName(selector);
  }

  /** @type {string} */
  const scrollspyString = 'scrollspy';

  /** @type {string} */
  const scrollspyComponent = 'ScrollSpy';

  /* Native JavaScript for Bootstrap 5 | ScrollSpy
  ------------------------------------------------ */

  // console.log(typeof addEventListener)

  // SCROLLSPY PRIVATE GC
  // ====================
  const scrollspySelector = '[data-bs-spy="scroll"]';

  const scrollspyDefaults = {
    offset: 10,
    target: null,
  };

  /**
   * Static method which returns an existing `ScrollSpy` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<ScrollSpy>}
   */
  const getScrollSpyInstance = (element) => getInstance(element, scrollspyComponent);

  /**
   * A `ScrollSpy` initialization callback.
   * @type {BSN.InitCallback<ScrollSpy>}
   */
  const scrollspyInitCallback = (element) => new ScrollSpy(element);

  // SCROLLSPY CUSTOM EVENT
  // ======================
  const activateScrollSpy = OriginalEvent(`activate.bs.${scrollspyString}`);

  // SCROLLSPY PRIVATE METHODS
  // =========================
  /**
   * Update the state of all items.
   * @param {ScrollSpy} self the `ScrollSpy` instance
   */
  function updateSpyTargets(self) {
    const {
      target, scrollTarget, options, itemsLength, scrollHeight, element,
    } = self;
    const { offset } = options;
    const isWin = scrollTarget instanceof Window;

    const links = target && getElementsByTagName('A', target);
    const scrollHEIGHT = scrollTarget && getScrollHeight(scrollTarget);

    // @ts-ignore
    self.scrollTop = isWin ? scrollTarget.scrollY : scrollTarget.scrollTop;

    // only update items/offsets once or with each mutation
    if (links && (itemsLength !== links.length || scrollHEIGHT !== scrollHeight)) {
      let href;
      let targetItem;
      let rect;

      // reset arrays & update
      self.items = [];
      self.offsets = [];
      self.scrollHeight = scrollHEIGHT;
      self.maxScroll = self.scrollHeight - getOffsetHeight(self);

      [...links].forEach((link) => {
        href = getAttribute(link, 'href');
        targetItem = href && href.charAt(0) === '#' && href.slice(-1) !== '#'
          && querySelector(href, getDocument(element));

        if (targetItem) {
          self.items.push(link);
          rect = getBoundingClientRect(targetItem);
          // @ts-ignore
          self.offsets.push((isWin ? rect.top + self.scrollTop : targetItem.offsetTop) - offset);
        }
      });
      self.itemsLength = self.items.length;
    }
  }

  /**
   * Returns the `scrollHeight` property of the scrolling element.
   * @param {HTMLElement | Element | Window | globalThis} scrollTarget the `ScrollSpy` instance
   * @return {number} `scrollTarget` height
   */
  function getScrollHeight(scrollTarget) {
    return scrollTarget instanceof HTMLElement
      ? scrollTarget.scrollHeight // @ts-ignore
      : getDocumentElement(scrollTarget).scrollHeight;
  }

  /**
   * Returns the height property of the scrolling element.
   * @param {ScrollSpy} params the `ScrollSpy` instance
   * @returns {number}
   */
  function getOffsetHeight({ element, scrollTarget }) {
    return (scrollTarget instanceof Window)
      ? scrollTarget.innerHeight
      : getBoundingClientRect(element).height;
  }

  /**
   * Clear all items of the target.
   * @param {HTMLElement | Element} target a single item
   */
  function clear(target) {
    [...getElementsByTagName('A', target)].forEach((item) => {
      if (hasClass(item, activeClass)) removeClass(item, activeClass);
    });
  }

  /**
   * Activates a new item.
   * @param {ScrollSpy} self the `ScrollSpy` instance
   * @param {HTMLElement | Element} item a single item
   */
  function activate(self, item) {
    const { target, element } = self;
    // @ts-ignore
    clear(target);
    // @ts-ignore
    self.activeItem = item;
    addClass(item, activeClass);

    // activate all parents
    const parents = [];
    let parentItem = item;
    while (parentItem !== getDocumentBody(element)) {
      // @ts-ignore
      parentItem = parentItem.parentElement;
      if (hasClass(parentItem, 'nav') || hasClass(parentItem, 'dropdown-menu')) parents.push(parentItem);
    }

    parents.forEach((menuItem) => {
      /** @type {(HTMLElement | Element)?} */
      const parentLink = menuItem.previousElementSibling;

      if (parentLink && !hasClass(parentLink, activeClass)) {
        addClass(parentLink, activeClass);
      }
    });

    // dispatch
    activateScrollSpy.relatedTarget = item;
    dispatchEvent(element, activateScrollSpy);
  }

  /**
   * Toggles on/off the component event listener.
   * @param {ScrollSpy} self the `ScrollSpy` instance
   * @param {boolean=} add when `true`, listener is added
   */
  function toggleSpyHandlers(self, add) {
    const action = add ? addListener : removeListener;
    // @ts-ignore
    action(self.scrollTarget, scrollEvent, self.refresh, passiveHandler);
  }

  // SCROLLSPY DEFINITION
  // ====================
  /** Returns a new `ScrollSpy` instance. */
  class ScrollSpy extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target the target element
     * @param {BSN.Options.ScrollSpy=} config the instance options
     */
    constructor(target, config) {
      super(target, config);
      // bind
      const self = this;

      // initialization element & options
      const { element, options } = self;

      // additional properties
      /** @type {(HTMLElement | Element)?} */
      self.target = querySelector(options.target, getDocument(element));

      // invalidate
      if (!self.target) return;

      const win = getWindow(element);

      // set initial state
      /** @type {HTMLElement | Element | Window | globalThis} */
      self.scrollTarget = element.clientHeight < element.scrollHeight ? element : win;
      /** @type {number} */
      self.scrollTop = 0;
      /** @type {number} */
      self.maxScroll = 0;
      /** @type {number} */
      self.scrollHeight = 0;
      /** @type {(HTMLElement | Element)?} */
      self.activeItem = null;
      /** @type {(HTMLElement | Element)[]} */
      self.items = [];
      /** @type {number} */
      self.itemsLength = 0;
      /** @type {number[]} */
      self.offsets = [];

      // bind events
      self.refresh = self.refresh.bind(self);

      // add event handlers
      toggleSpyHandlers(self, true);

      self.refresh();
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return scrollspyComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return scrollspyDefaults; }
    /* eslint-enable */

    // SCROLLSPY PUBLIC METHODS
    // ========================
    /** Updates all items. */
    refresh() {
      const self = this;
      const { target } = self;

      // check if target is visible and invalidate
      // @ts-ignore
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
        // @ts-ignore
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

    /** Removes `ScrollSpy` from the target element. */
    dispose() {
      toggleSpyHandlers(this);
      super.dispose();
    }
  }

  ObjectAssign(ScrollSpy, {
    selector: scrollspySelector,
    init: scrollspyInitCallback,
    getInstance: getScrollSpyInstance,
  });

  /**
   * A global namespace for aria-selected.
   * @type {string}
   */
  const ariaSelected = 'aria-selected';

  /** @type {string} */
  const tabString = 'tab';

  /** @type {string} */
  const tabComponent = 'Tab';

  /* Native JavaScript for Bootstrap 5 | Tab
  ------------------------------------------ */

  // TAB PRIVATE GC
  // ================
  const tabSelector = `[${dataBsToggle}="${tabString}"]`;

  /**
   * Static method which returns an existing `Tab` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Tab>}
   */
  const getTabInstance = (element) => getInstance(element, tabComponent);

  /**
   * A `Tab` initialization callback.
   * @type {BSN.InitCallback<Tab>}
   */
  const tabInitCallback = (element) => new Tab(element);

  // TAB CUSTOM EVENTS
  // =================
  const showTabEvent = OriginalEvent(`show.bs.${tabString}`);
  const shownTabEvent = OriginalEvent(`shown.bs.${tabString}`);
  const hideTabEvent = OriginalEvent(`hide.bs.${tabString}`);
  const hiddenTabEvent = OriginalEvent(`hidden.bs.${tabString}`);

  /**
   * @type {Map<(HTMLElement | Element), any>}
   */
  const tabPrivate = new Map();

  // TAB PRIVATE METHODS
  // ===================
  /**
   * Executes after tab transition has finished.
   * @param {Tab} self the `Tab` instance
   */
  function triggerTabEnd(self) {
    const { tabContent, nav } = self;

    if (tabContent) {
      // @ts-ignore
      tabContent.style.height = '';
      removeClass(tabContent, collapsingClass);
    }

    if (nav) Timer.clear(nav);
  }

  /**
   * Executes before showing the tab content.
   * @param {Tab} self the `Tab` instance
   */
  function triggerTabShow(self) {
    const { element, tabContent, nav } = self;
    const { currentHeight, nextHeight } = tabPrivate.get(element);
    const { tab } = nav && tabPrivate.get(nav);

    if (tabContent) { // height animation
      if (currentHeight === nextHeight) {
        triggerTabEnd(self);
      } else {
        setTimeout(() => { // enables height animation
          // @ts-ignore
          tabContent.style.height = `${nextHeight}px`; // height animation
          reflow(tabContent);
          emulateTransitionEnd(tabContent, () => triggerTabEnd(self));
        }, 50);
      }
    } else if (nav) Timer.clear(nav);
    shownTabEvent.relatedTarget = tab;
    dispatchEvent(element, shownTabEvent);
  }

  /**
   * Executes before hiding the tab.
   * @param {Tab} self the `Tab` instance
   */
  function triggerTabHide(self) {
    const {
      element, content: nextContent, tabContent, nav,
    } = self;
    const { tab, content } = nav && tabPrivate.get(nav);
    let currentHeight = 0;

    if (tabContent) {
      [content, nextContent].forEach((c) => addClass(c, 'overflow-hidden'));
      currentHeight = content.scrollHeight;
    }

    // update relatedTarget and dispatch event
    showTabEvent.relatedTarget = tab;
    hiddenTabEvent.relatedTarget = element;
    dispatchEvent(element, showTabEvent);
    if (showTabEvent.defaultPrevented) return;

    addClass(nextContent, activeClass);
    removeClass(content, activeClass);

    if (tabContent) {
      const nextHeight = nextContent.scrollHeight;
      tabPrivate.set(element, { currentHeight, nextHeight });

      addClass(tabContent, collapsingClass);
      // @ts-ignore -- height animation
      tabContent.style.height = `${currentHeight}px`;
      reflow(tabContent);
      [content, nextContent].forEach((c) => removeClass(c, 'overflow-hidden'));
    }

    if (nextContent && hasClass(nextContent, fadeClass)) {
      setTimeout(() => {
        addClass(nextContent, showClass);
        emulateTransitionEnd(nextContent, () => {
          triggerTabShow(self);
        });
      }, 17);
    } else { triggerTabShow(self); }

    dispatchEvent(tab, hiddenTabEvent);
  }

  /**
   * Returns the current active tab and its target content.
   * @param {Tab} self the `Tab` instance
   * @returns {Record<string, any>} the query result
   */
  function getActiveTab(self) {
    const { nav } = self;

    // @ts-ignore
    const activeTabs = getElementsByClassName(activeClass, nav);
    /** @type {(HTMLElement | Element)=} */
    let tab;
    if (activeTabs.length === 1
      // @ts-ignore
      && !dropdownMenuClasses.some((c) => hasClass(activeTabs[0].parentElement, c))) {
      [tab] = activeTabs;
    } else if (activeTabs.length > 1) {
      tab = activeTabs[activeTabs.length - 1];
    }
    const content = tab ? getTargetElement(tab) : null;
    // @ts-ignore
    return { tab, content };
  }

  /**
   * Toggles on/off the `click` event listener.
   * @param {Tab} self the `Tab` instance
   * @param {boolean=} add when `true`, event listener is added
   */
  function toggleTabHandler(self, add) {
    const action = add ? addListener : removeListener;
    action(self.element, mouseclickEvent, tabClickHandler);
  }

  // TAB EVENT HANDLER
  // =================
  /**
   * Handles the `click` event listener.
   * @this {HTMLElement | Element}
   * @param {MouseEvent} e the `Event` object
   */
  function tabClickHandler(e) {
    const self = getTabInstance(this);
    if (!self) return;
    e.preventDefault();

    self.show();
  }

  // TAB DEFINITION
  // ==============
  /** Creates a new `Tab` instance. */
  class Tab extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target the target element
     */
    constructor(target) {
      super(target);
      // bind
      const self = this;

      // initialization element
      const { element } = self;
      const content = getTargetElement(element);

      // no point initializing a tab without a corresponding content
      if (!content) return;

      const nav = closest(element, '.nav');
      const container = closest(content, '.tab-content');

      /** @type {(HTMLElement | Element)?} */
      self.nav = nav;
      /** @type {HTMLElement | Element} */
      self.content = content;
      /** @type {(HTMLElement | Element)?} */
      self.tabContent = container;

      // event targets
      /** @type {(HTMLElement | Element)?} */
      self.dropdown = nav && querySelector(`.${dropdownMenuClasses[0]}-toggle`, nav);

      // add event listener
      toggleTabHandler(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return tabComponent; }
    /* eslint-enable */

    // TAB PUBLIC METHODS
    // ==================
    /** Shows the tab to the user. */
    show() {
      const self = this;
      const { element, nav, dropdown } = self;

      if (!(nav && Timer.get(nav)) && !hasClass(element, activeClass)) {
        const { tab, content } = getActiveTab(self);

        if (nav) tabPrivate.set(nav, { tab, content });

        // update relatedTarget and dispatch
        hideTabEvent.relatedTarget = element;
        dispatchEvent(tab, hideTabEvent);
        if (hideTabEvent.defaultPrevented) return;

        if (nav) Timer.set(nav, () => {}, 17);
        removeClass(tab, activeClass);
        setAttribute(tab, ariaSelected, 'false');
        addClass(element, activeClass);
        setAttribute(element, ariaSelected, 'true');

        if (dropdown) {
          // @ts-ignore
          if (!hasClass(element.parentNode, dropdownMenuClass)) {
            if (hasClass(dropdown, activeClass)) removeClass(dropdown, activeClass);
          } else if (!hasClass(dropdown, activeClass)) addClass(dropdown, activeClass);
        }

        if (hasClass(content, fadeClass)) {
          removeClass(content, showClass);
          emulateTransitionEnd(content, () => triggerTabHide(self));
        } else {
          triggerTabHide(self);
        }
      }
    }

    /** Removes the `Tab` component from the target element. */
    dispose() {
      toggleTabHandler(this);
      super.dispose();
    }
  }

  ObjectAssign(Tab, {
    selector: tabSelector,
    init: tabInitCallback,
    getInstance: getTabInstance,
  });

  /** @type {string} */
  const toastString = 'toast';

  /** @type {string} */
  const toastComponent = 'Toast';

  /* Native JavaScript for Bootstrap 5 | Toast
  -------------------------------------------- */

  // TOAST PRIVATE GC
  // ================
  const toastSelector = `.${toastString}`;
  const toastDismissSelector = `[${dataBsDismiss}="${toastString}"]`;
  const showingClass = 'showing';
  /** @deprecated */
  const hideClass = 'hide';

  const toastDefaults = {
    animation: true,
    autohide: true,
    delay: 5000,
  };

  /**
   * Static method which returns an existing `Toast` instance associated
   * to a target `Element`.
   *
   * @type {BSN.GetInstance<Toast>}
   */
  const getToastInstance = (element) => getInstance(element, toastComponent);

  /**
   * A `Toast` initialization callback.
   * @type {BSN.InitCallback<Toast>}
   */
  const toastInitCallback = (element) => new Toast(element);

  // TOAST CUSTOM EVENTS
  // ===================
  const showToastEvent = OriginalEvent(`show.bs.${toastString}`);
  const shownToastEvent = OriginalEvent(`shown.bs.${toastString}`);
  const hideToastEvent = OriginalEvent(`hide.bs.${toastString}`);
  const hiddenToastEvent = OriginalEvent(`hidden.bs.${toastString}`);

  // TOAST PRIVATE METHODS
  // =====================
  /**
   * Executes after the toast is shown to the user.
   * @param {Toast} self the `Toast` instance
   */
  function showToastComplete(self) {
    const { element, options } = self;
    removeClass(element, showingClass);
    Timer.clear(element, showingClass);

    dispatchEvent(element, shownToastEvent);
    if (options.autohide) {
      Timer.set(element, () => self.hide(), options.delay, toastString);
    }
  }

  /**
   * Executes after the toast is hidden to the user.
   * @param {Toast} self the `Toast` instance
   */
  function hideToastComplete(self) {
    const { element } = self;
    removeClass(element, showingClass);
    removeClass(element, showClass);
    addClass(element, hideClass); // B/C
    Timer.clear(element, toastString);
    dispatchEvent(element, hiddenToastEvent);
  }

  /**
   * Executes before hiding the toast.
   * @param {Toast} self the `Toast` instance
   */
  function hideToast(self) {
    const { element, options } = self;
    addClass(element, showingClass);

    if (options.animation) {
      reflow(element);
      emulateTransitionEnd(element, () => hideToastComplete(self));
    } else {
      hideToastComplete(self);
    }
  }

  /**
   * Executes before showing the toast.
   * @param {Toast} self the `Toast` instance
   */
  function showToast(self) {
    const { element, options } = self;
    Timer.set(element, () => {
      removeClass(element, hideClass); // B/C
      reflow(element);
      addClass(element, showClass);
      addClass(element, showingClass);

      if (options.animation) {
        emulateTransitionEnd(element, () => showToastComplete(self));
      } else {
        showToastComplete(self);
      }
    }, 17, showingClass);
  }

  /**
   * Toggles on/off the `click` event listener.
   * @param {Toast} self the `Toast` instance
   * @param {boolean=} add when `true`, it will add the listener
   */
  function toggleToastHandlers(self, add) {
    const action = add ? addListener : removeListener;
    const { element, dismiss, options } = self;
    if (dismiss) {
      action(dismiss, mouseclickEvent, self.hide);
    }
    if (options.autohide) {
      [focusinEvent, focusoutEvent, mouseenterEvent, mouseleaveEvent]
        .forEach((e) => action(element, e, interactiveToastHandler));
    }
  }

  // TOAST EVENT HANDLERS
  // ====================
  /**
   * Executes after the instance has been disposed.
   * @param {Toast} self the `Toast` instance
   */
  function completeDisposeToast(self) {
    Timer.clear(self.element, toastString);
    toggleToastHandlers(self);
  }

  /**
   * Executes when user interacts with the toast without closing it,
   * usually by hovering or focusing it.
   *
   * @this {HTMLElement | Element}
   * @param {MouseEvent} e the `Toast` instance
   */
  function interactiveToastHandler(e) {
    const element = this;
    const self = getToastInstance(element);
    const { type, relatedTarget } = e;
    // @ts-ignore
    if (!self || (element === relatedTarget || element.contains(relatedTarget))) return;

    if ([mouseenterEvent, focusinEvent].includes(type)) {
      Timer.clear(element, toastString);
    } else {
      Timer.set(element, () => self.hide(), self.options.delay, toastString);
    }
  }

  // TOAST DEFINITION
  // ================
  /** Creates a new `Toast` instance. */
  class Toast extends BaseComponent {
    /**
     * @param {HTMLElement | Element | string} target the target `.toast` element
     * @param {BSN.Options.Toast=} config the instance options
     */
    constructor(target, config) {
      super(target, config);
      // bind
      const self = this;
      const { element, options } = self;

      // set fadeClass, the options.animation will override the markup
      if (options.animation && !hasClass(element, fadeClass)) addClass(element, fadeClass);
      else if (!options.animation && hasClass(element, fadeClass)) removeClass(element, fadeClass);
      // dismiss button
      /** @type {(HTMLElement | Element)?} */
      self.dismiss = querySelector(toastDismissSelector, element);

      // bind
      self.show = self.show.bind(self);
      self.hide = self.hide.bind(self);

      // add event listener
      toggleToastHandlers(self, true);
    }

    /* eslint-disable */
    /**
     * Returns component name string.
     * @readonly @static
     */
    get name() { return toastComponent; }
    /**
     * Returns component default options.
     * @readonly @static
     */
    get defaults() { return toastDefaults; }
    /* eslint-enable */

    // TOAST PUBLIC METHODS
    // ====================
    /** Shows the toast. */
    show() {
      const self = this;
      const { element } = self;
      if (element && !hasClass(element, showClass)) {
        dispatchEvent(element, showToastEvent);
        if (showToastEvent.defaultPrevented) return;

        showToast(self);
      }
    }

    /** Hides the toast. */
    hide() {
      const self = this;
      const { element } = self;

      if (element && hasClass(element, showClass)) {
        dispatchEvent(element, hideToastEvent);
        if (hideToastEvent.defaultPrevented) return;
        hideToast(self);
      }
    }

    /** Removes the `Toast` component from the target element. */
    dispose() {
      const self = this;
      const { element } = self;

      if (hasClass(element, showClass)) {
        removeClass(element, showClass);
      }

      completeDisposeToast(self);

      super.dispose();
    }
  }

  ObjectAssign(Toast, {
    selector: toastSelector,
    init: toastInitCallback,
    getInstance: getToastInstance,
  });

  /**
   * Check if element matches a CSS selector.
   *
   * @param {HTMLElement | Element} target
   * @param {string} selector
   * @returns {boolean}
   */
  function matches(target, selector) {
    return target.matches(selector);
  }

  /** @type {Record<string, any>} */
  const componentsList = {
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
  };

  /**
   * Initialize all matched `Element`s for one component.
   * @param {BSN.InitCallback<any>} callback
   * @param {NodeListOf<HTMLElement | Element> | (HTMLElement | Element)[]} collection
   */
  function initComponentDataAPI(callback, collection) {
    [...collection].forEach((x) => callback(x));
  }

  /**
   * Remove one component from a target container element or all in the page.
   * @param {string} component the component name
   * @param {(Element | HTMLElement | Document)=} context parent `Element`
   */
  function removeComponentDataAPI(component, context) {
    const compData = Data.getAllFor(component);

    if (compData) {
      [...compData].forEach((x) => {
        const [element, instance] = x;
        if (context && context.contains(element)) instance.dispose();
      });
    }
  }

  /**
   * Initialize all BSN components for a target container.
   * @param {(Element | HTMLElement | Document)=} context parent `Element`
   */
  function initCallback(context) {
    const lookUp = context && parentNodes.some((x) => context instanceof x)
      ? context : undefined;
    const elemCollection = [...getElementsByTagName('*', lookUp)];

    ObjectKeys(componentsList).forEach((comp) => {
      const { init, selector } = componentsList[comp];
      initComponentDataAPI(init, elemCollection.filter((item) => matches(item, selector)));
    });
  }

  /**
   * Remove all BSN components for a target container.
   * @param {(Element | HTMLElement | Document)=} context parent `Element`
   */
  function removeDataAPI(context) {
    const lookUp = context && parentNodes.some((x) => context instanceof x)
      ? context : undefined;

    ObjectKeys(componentsList).forEach((comp) => {
      removeComponentDataAPI(comp, lookUp);
    });
  }

  // bulk initialize all components
  if (document.body) initCallback();
  else {
    addListener(document, 'DOMContentLoaded', () => initCallback(), { once: true });
  }

  const BSN = {
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
    removeDataAPI,
    Version,
    EventListener,
  };

  return BSN;

}));
