<script>
  export let data;
  export let form;

  import {
    ButtonGroup,
    Drawer,
    Table,
    TableHead,
    TableHeadCell,
    TableBody,
    TableBodyRow,
    TableBodyCell,
    Select,
  } from "flowbite-svelte";
  import dayjs from "dayjs";
  import { Button, Modal, Label, Input } from "flowbite-svelte";
  let values = [
    {
      ip_or_hostname: "",
    },
  ];


  const addField = () => {
    values = [...values, { ip_or_hostname: "" }];
  };

  const removeField = () => {
    values = values.slice(0, values.length - 1);
  };
</script>

<form class="flex flex-col space-y-6" action="?/submit" method="POST">
  <h3 class="mb-4 text-xl font-medium text-gray-900 dark:text-white">
    Scan IPs & Hosts
  </h3>
  {#each values as value, i}
    <Label class="space-y-2">
      <span>IP or Host (eg. 34.117.168.233 or www.google.com')</span>
      <Input type="text" name="ip_or_hostname" required />
    </Label>
  {/each}
  {#if values.length > 1}
    <!-- <Button type="button" color="red" on:click={removeField}>Remove Field</Button> -->
  {/if}
  <Button type="submit" color="red" class="w-full1">Submit</Button>
  <!-- <Button type="button" color="red" on:click={addField}>Add Field</Button> -->
  {#if form}
    <div class="mt-4 text-red-500">
      {#if !form?.success}
          <p>{form?.message.error}</p>
      {:else}
        <p>There was an error submitting the form. Please validate your entry and try again.</p>
      {/if}
    </div>
  {/if}
</form>


<!-- todo: needs refactor. this was coppied from another application -->
<div class="results-tables">
  Host Data:
  <Table>
    <TableHead>
      <TableHeadCell>IP Address</TableHeadCell>
      <TableHeadCell>Hostname</TableHeadCell>
    </TableHead>
    <TableBody>
      {#if form?.success && form.hostData}
        <TableBodyRow>
          <TableBodyCell>{form.hostData.ip_address}</TableBodyCell>
          <TableBodyCell>{form.hostData.hostname}</TableBodyCell>
        </TableBodyRow>
      {:else}
        <TableBodyRow>
          <TableBodyCell colspan="2">No host data found</TableBodyCell>
        </TableBodyRow>
      {/if}
    </TableBody>
  </Table>

  Changes:
  <Table>
    <TableHead>
      <TableHeadCell>Port</TableHeadCell>
      <TableHeadCell>Change</TableHeadCell>
    </TableHead>
    <TableBody>
      {#if form?.success && form.changes}
        {#each Object.entries(form.changes) as [port, change]}
          <TableBodyRow>
            <TableBodyCell>{port}</TableBodyCell>
            <TableBodyCell>{change}</TableBodyCell>
          </TableBodyRow>
        {/each}
      {:else}
        <TableBodyRow>
          <TableBodyCell colspan="2">No changes found</TableBodyCell>
        </TableBodyRow>
      {/if}
    </TableBody>
  </Table>

  Scan Results:
  <Table>
    <TableHead>
      <TableHeadCell>IP Address</TableHeadCell>
      <TableHeadCell>Scan Time</TableHeadCell>
      <TableHeadCell>Port</TableHeadCell>
      <TableHeadCell>Status</TableHeadCell>
    </TableHead>
    <TableBody>
      {#if form?.success && form.scanResults}
        {#each form.scanResults as result}
          <TableBodyRow>
            <TableBodyCell>{result.ip_address}</TableBodyCell>
            <TableBodyCell>{dayjs(result.scan_time).format("HH:mm:ss MM/DD/YYYY")}</TableBodyCell>
            <TableBodyCell>{result.port}</TableBodyCell>
            <TableBodyCell>{result.status}</TableBodyCell>
          </TableBodyRow>
        {/each}
      {/if}
    </TableBody>
  </Table>

  Historical Scan Data:
  <Table>
    <TableHead>
      <TableHeadCell>Port</TableHeadCell>
      <TableHeadCell>Scan Time</TableHeadCell>
      <TableHeadCell>Status</TableHeadCell>
      <!-- <TableHeadCell>IP Address</TableHeadCell> -->
    </TableHead>
    <TableBody>
      {#if form?.success && form.portHistory}
        {#each form.portHistory as result}
          <TableBodyRow>
            <TableBodyCell>{result.port}</TableBodyCell>
            <TableBodyCell>{dayjs(result.scan_time).format("HH:mm:ss MM/DD/YYYY")}</TableBodyCell>
            <TableBodyCell>{result.status}</TableBodyCell>
            <!-- <TableBodyCell>{result.ip_address}</TableBodyCell> -->
          </TableBodyRow>
        {/each}
      {/if}
    </TableBody>
  </Table>
</div>


<style>
  /* add some styling so that the form is centered and has width about a third of the screen */
  form {
    width: 30%;
    margin: 0 auto;
  }
  /* center the table like we did the form */
  .results-tables {
    width: 60%;
    margin: 0 auto;
  }
</style>
