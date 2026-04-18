const fs = require('fs');
const d3 = require('d3');
const { JSDOM } = require('jsdom');

const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
const document = dom.window.document;

function createReadmeChart() {
    const width = 420;
    const height = 290;
    const margin = {top: 45, bottom: 20, left: 90, gap: 40};
    
    // Width for the actual bars + values
    const plotWidth = width - margin.left - 20; 
    const maxBarWidth = plotWidth - 50; 

    const svg = d3.select(document.body)
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('xmlns', 'http://www.w3.org/2000/svg');

    // Widget Background
    svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr('rx', 12)
        .attr('fill', '#ffffff')
        .attr('stroke', '#E5E7EB')
        .attr('stroke-width', 1);

    const data = [
        { tool: 'Pyscan', time: 7.9, mem: 54 },
        { tool: 'Pip-audit', time: 41.7, mem: 426 },
        { tool: 'Safety', time: 18.2, mem: 120 }
    ];

    const color = d3.scaleOrdinal()
        .domain(['Pyscan', 'Pip-audit', 'Safety'])
        .range(['#F4A261', '#9CA3AF', '#2A9D8F']);
        
    const textColor = d3.scaleOrdinal()
        .domain(['Pyscan', 'Pip-audit', 'Safety'])
        .range(['#D97D3A', '#6B7280', '#1C7267']);

    // Each subplot gets a height of ~80px
    const innerHeight = 80;

    const y = d3.scaleBand()
        .domain(['Pyscan', 'Pip-audit', 'Safety'])
        .rangeRound([0, innerHeight])
        .paddingInner(0.3)
        .paddingOuter(0.1);

    // ---- TOP SUBPLOT: TIME ----
    const gTime = svg.append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);
        
    const xTime = d3.scaleLinear()
        .domain([0, 45])
        .range([0, maxBarWidth]);

    // Title Time
    const titleTime = gTime.append('text')
        .attr('x', -margin.left + 24)
        .attr('y', -20)
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .attr('text-anchor', 'start');
        
    titleTime.append('tspan')
        .style('font-size', '14px')
        .style('font-weight', '600')
        .style('fill', '#111827')
        .text('Execution Time ');
        
    titleTime.append('tspan')
        .style('font-size', '13px')
        .style('font-weight', '400')
        .style('fill', '#9CA3AF')
        .text('(88 deps)');

    // Labels Time
    gTime.selectAll('.tool-label')
        .data(data)
        .join('text')
        .attr('class', 'tool-label')
        .attr('x', -12)
        .attr('y', d => y(d.tool) + y.bandwidth() / 2)
        .attr('dy', '0.32em')
        .attr('text-anchor', 'end')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '13px')
        .style('font-weight', '600')
        .style('fill', '#4B5563')
        .text(d => d.tool);

    // Bars Time
    gTime.selectAll('rect')
        .data(data)
        .join('rect')
        .attr('x', 0)
        .attr('y', d => y(d.tool))
        .attr('width', d => xTime(d.time))
        .attr('height', y.bandwidth())
        .attr('fill', d => color(d.tool))
        .attr('rx', 4);

    // Values Time
    gTime.selectAll('.val-label')
        .data(data)
        .join('text')
        .attr('class', 'val-label')
        .attr('x', d => xTime(d.time) + 8)
        .attr('y', d => y(d.tool) + y.bandwidth() / 2)
        .attr('dy', '0.32em')
        .attr('text-anchor', 'start')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '13px')
        .style('font-weight', '600')
        .style('fill', d => textColor(d.tool))
        .text(d => d.time + 's');


    // Divider line horizontal
    const dividerY = margin.top + innerHeight + (margin.gap / 2);
    svg.append('line')
        .attr('x1', 20)
        .attr('y1', dividerY)
        .attr('x2', width - 20)
        .attr('y2', dividerY)
        .attr('stroke', '#F3F4F6')
        .attr('stroke-width', 2)
        .attr('stroke-linecap', 'round');

    // ---- BOTTOM SUBPLOT: MEMORY ----
    const gMem = svg.append('g')
        .attr('transform', `translate(${margin.left},${dividerY + margin.top})`);
        
    const xMem = d3.scaleLinear()
        .domain([0, 450]) 
        .range([0, maxBarWidth]);

    // Title Mem
    const titleMem = gMem.append('text')
        .attr('x', -margin.left + 24)
        .attr('y', -20)
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .attr('text-anchor', 'start');
        
    titleMem.append('tspan')
        .style('font-size', '14px')
        .style('font-weight', '600')
        .style('fill', '#111827')
        .text('Peak Memory ');

    titleMem.append('tspan')
        .style('font-size', '13px')
        .style('font-weight', '400')
        .style('fill', '#9CA3AF')
        .text('(RSS)');

    // Labels Mem
    gMem.selectAll('.tool-label')
        .data(data)
        .join('text')
        .attr('class', 'tool-label')
        .attr('x', -12)
        .attr('y', d => y(d.tool) + y.bandwidth() / 2)
        .attr('dy', '0.32em')
        .attr('text-anchor', 'end')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '13px')
        .style('font-weight', '600')
        .style('fill', '#4B5563')
        .text(d => d.tool);

    // Bars Mem
    gMem.selectAll('rect')
        .data(data)
        .join('rect')
        .attr('x', 0)
        .attr('y', d => y(d.tool))
        .attr('width', d => xMem(d.mem))
        .attr('height', y.bandwidth())
        .attr('fill', d => color(d.tool))
        .attr('rx', 4);

    // Values Mem
    gMem.selectAll('.val-label')
        .data(data)
        .join('text')
        .attr('class', 'val-label')
        .attr('x', d => xMem(d.mem) + 8)
        .attr('y', d => y(d.tool) + y.bandwidth() / 2)
        .attr('dy', '0.32em')
        .attr('text-anchor', 'start')
        .style('font-family', '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif')
        .style('font-size', '13px')
        .style('font-weight', '600')
        .style('fill', d => textColor(d.tool))
        .text(d => d.mem + ' MB');


    fs.writeFileSync(__dirname + '/readme_benchmark.svg', svg.node().outerHTML);
    d3.select(document.body).selectAll('*').remove();
}

createReadmeChart();
console.log("README SVG generated vertically.");
