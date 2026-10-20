/**
 * Lucide Safe Adapter for Vue 3 & Dynamic Frameworks
 * 
 * Standard lucide.createIcons() uses parentNode.replaceChild(), which replaces the <i>
 * DOM node that Vue manages in its Virtual DOM tree. When Vue re-renders or patches,
 * this causes "TypeError: can't access property '__vnode', el is null".
 * 
 * This adapter intercepts lucide.createIcons() to safely inject the SVG *inside* the
 * <i> element instead of replacing it, preserving Vue's VNode bindings and DOM tree integrity.
 */
(function () {
    if (typeof window === 'undefined') return;

    function toPascalCase(str) {
        if (!str) return '';
        return str.replace(/(^\w|-\w)/g, function (c) {
            return c.replace('-', '').toUpperCase();
        });
    }

    function patchLucide() {
        if (!window.lucide) return;

        window.lucide.createIcons = function (options) {
            options = options || {};
            var root = options.root || document;
            var elements = root.querySelectorAll('[data-lucide]');

            elements.forEach(function (el) {
                var name = el.getAttribute('data-lucide');
                if (!name) return;

                // If already rendered with this icon, skip
                if (el.dataset.renderedIcon === name && el.firstElementChild) return;

                var pascal = toPascalCase(name);
                var iconData = (window.lucide.icons && window.lucide.icons[pascal]) || window.lucide[pascal];
                if (!iconData) return;

                try {
                    var svg = window.lucide.createElement(iconData);
                    svg.setAttribute('class', 'lucide lucide-' + name + ' w-full h-full');
                    svg.setAttribute('stroke', 'currentColor');

                    // Preserve <i> element in Vue's VDOM by inserting svg inside it
                    el.innerHTML = '';
                    el.appendChild(svg);
                    el.dataset.renderedIcon = name;
                } catch (err) {
                    console.warn('[LucideSafe] Failed to render icon:', name, err);
                }
            });
        };

        // Immediately run safe createIcons for any existing elements
        window.lucide.createIcons();
    }

    if (window.lucide) {
        patchLucide();
    } else {
        document.addEventListener('DOMContentLoaded', patchLucide);
    }
})();
